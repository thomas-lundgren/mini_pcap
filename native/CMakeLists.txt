cmake_minimum_required(VERSION 3.18)
project(mpc_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LWIP_DIR ${CMAKE_CURRENT_LIST_DIR}/../third_party/lwip)

file(GLOB LWIP_SRC
    ${LWIP_DIR}/src/core/*.c
    ${LWIP_DIR}/src/core/ipv4/*.c
    ${LWIP_DIR}/src/core/ipv6/*.c)
list(APPEND LWIP_SRC ${LWIP_DIR}/src/ports/lib/mem.c)

add_library(mpc_lwip STATIC ${LWIP_SRC})
target_include_directories(mpc_lwip PUBLIC ${LWIP_DIR}/src/include ${LWIP_DIR}/src/ports/include)
target_compile_options(mpc_lwip PRIVATE -O2 -w -fno-stack-clash-protection)
target_compile_definitions(mpc_lwip PUBLIC FD_SET_DEFINED SOCKLEN_T_DEFINED)
set_target_properties(mpc_lwip PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Capture core: no lwIP dependency, host-testable.
add_library(mpc_capture STATIC
    src/packet.c src/flow.c src/ring.c src/pcap.c src/capture.c)
target_include_directories(mpc_capture PUBLIC include)
target_compile_options(mpc_capture PRIVATE -O2 -Wall -Wextra -Wno-unused-parameter)
set_target_properties(mpc_capture PROPERTIES POSITION_INDEPENDENT_CODE ON)
find_package(Threads REQUIRED)
target_link_libraries(mpc_capture PUBLIC Threads::Threads)

add_library(mpc_engine STATIC src/engine.c src/relay_tcp.c src/relay_udp.c)
target_link_libraries(mpc_engine PUBLIC mpc_capture mpc_lwip)
target_compile_options(mpc_engine PRIVATE -O2 -Wall -Wno-unused-parameter)
set_target_properties(mpc_engine PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(MPC_TOOLS_ONLY)
    # Benchmark workload tool for adb push (validation/perf/build_nettool.sh).
    add_executable(nettool tools/nettool.c)
    target_compile_options(nettool PRIVATE -O2)
elseif(ANDROID)
    add_library(mpcnative SHARED src/jni.c)
    # Only the JNIEXPORT entry points are exported from the .so.
    set_target_properties(mpcnative mpc_engine mpc_capture mpc_lwip PROPERTIES C_VISIBILITY_PRESET hidden)
    target_link_libraries(mpcnative mpc_engine log)
    target_link_options(mpcnative PRIVATE -Wl,--gc-sections -Wl,-z,max-page-size=16384)
else()
    enable_testing()
    foreach(t test_pcap test_packet test_flow test_ring test_capture test_engine)
        add_executable(${t} tests/${t}.c)
        target_link_libraries(${t} mpc_engine)
        target_compile_options(${t} PRIVATE -O1 -g -Wall -Wno-unused-parameter)
    endforeach()
    add_test(NAME pcap COMMAND test_pcap)
    add_test(NAME packet COMMAND test_packet)
    add_test(NAME flow COMMAND test_flow)
    add_test(NAME ring COMMAND test_ring)
    add_test(NAME capture COMMAND test_capture ${CMAKE_CURRENT_BINARY_DIR}/fixture)
    add_test(NAME engine COMMAND test_engine)
    add_executable(nettool tools/nettool.c)
    target_compile_options(nettool PRIVATE -O2)
    # Performance micro-benchmark (built optimized regardless of the build type).
    add_executable(bench_capture tests/bench_capture.c)
    target_link_libraries(bench_capture mpc_engine)
    target_compile_options(bench_capture PRIVATE -O2 -Wall -Wno-unused-parameter)
endif()
