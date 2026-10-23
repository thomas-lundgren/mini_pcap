/* JNI bridge. Called only at session start/stop, for ~1 Hz counter snapshots and
 * context records, and for batched UID request/resolution exchange through direct
 * ByteBuffers. Nothing here runs per packet. */
#include <errno.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>

#include "mpc/engine.h"

#define TAG "mpcnative"

typedef struct {
    mpc_session *s;
    char *strs[5];
} handle_t;

static char *dup_jstring(JNIEnv *env, jstring js)
{
    if (!js)
        return NULL;
    const char *c = (*env)->GetStringUTFChars(env, js, NULL);
    char *d = c ? strdup(c) : NULL;
    if (c)
        (*env)->ReleaseStringUTFChars(env, js, c);
    return d;
}

JNIEXPORT jobjectArray JNICALL Java_dev_minipcap_capture_NativeCore_nativeCounterNames(JNIEnv *env,
                                                                                        jclass cls)
{
    jclass sc = (*env)->FindClass(env, "java/lang/String");
    jobjectArray arr = (*env)->NewObjectArray(env, MPC_CNT__COUNT, sc, NULL);
    for (int i = 0; i < MPC_CNT__COUNT; i++) {
        jstring s = (*env)->NewStringUTF(env, mpc_counter_names[i]);
        (*env)->SetObjectArrayElement(env, arr, i, s);
        (*env)->DeleteLocalRef(env, s);
    }
    return arr;
}

JNIEXPORT jlong JNICALL Java_dev_minipcap_capture_NativeCore_nativeStart(
    JNIEnv *env, jclass cls, jint tun_fd, jstring pcap_path, jint snaplen, jint mtu, jint variant,
    jint ring_bytes, jstring userappl, jstring os, jstring hardware, jint uid_hold_ms)
{
    handle_t *h = calloc(1, sizeof(*h));
    if (!h) {
        close(tun_fd);
        return -ENOMEM;
    }
    h->strs[0] = dup_jstring(env, pcap_path);
    h->strs[1] = dup_jstring(env, userappl);
    h->strs[2] = dup_jstring(env, os);
    h->strs[3] = dup_jstring(env, hardware);
    h->strs[4] = strdup("tun0");
    mpc_capture_config cfg = {
        .pcap_path = h->strs[0],
        .snaplen = (uint32_t)snaplen,
        .mtu = (uint32_t)mtu,
        .variant = variant,
        .ring_bytes = (size_t)ring_bytes,
        .if_name = h->strs[4],
        .userappl = h->strs[1],
        .os = h->strs[2],
        .hardware = h->strs[3],
        .uid_hold_ms = uid_hold_ms > 0 ? (uint32_t)uid_hold_ms : 0,
    };
    int err = 0;
    h->s = mpc_session_start(tun_fd, &cfg, &err);
    if (!h->s) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "session start failed: %d", err);
        for (int i = 0; i < 5; i++)
            free(h->strs[i]);
        free(h);
        return -(err ? err : EIO);
    }
    return (jlong)(intptr_t)h;
}

JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeStop(JNIEnv *env, jclass cls,
                                                                        jlong handle)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    return h ? mpc_session_stop(h->s) : -1;
}

JNIEXPORT void JNICALL Java_dev_minipcap_capture_NativeCore_nativeDestroy(JNIEnv *env, jclass cls,
                                                                           jlong handle)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    if (!h)
        return;
    mpc_session_destroy(h->s);
    for (int i = 0; i < 5; i++)
        free(h->strs[i]);
    free(h);
}

JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeCounters(JNIEnv *env, jclass cls,
                                                                            jlong handle,
                                                                            jlongArray out)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    if (!h)
        return 0;
    uint64_t v[MPC_CNT__COUNT];
    mpc_capture_snapshot(mpc_session_capture(h->s), v, MPC_CNT__COUNT);
    jsize n = (*env)->GetArrayLength(env, out);
    if (n > MPC_CNT__COUNT)
        n = MPC_CNT__COUNT;
    (*env)->SetLongArrayRegion(env, out, 0, n, (const jlong *)v);
    return n;
}

JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeUidPoll(JNIEnv *env, jclass cls,
                                                                           jlong handle, jobject buf,
                                                                           jint max, jint timeout_ms)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    void *p = (*env)->GetDirectBufferAddress(env, buf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, buf);
    if (!h || !p)
        return -1;
    if ((jlong)max * (jlong)sizeof(mpc_uid_request) > cap)
        max = (jint)(cap / (jlong)sizeof(mpc_uid_request));
    return mpc_capture_uid_poll(mpc_session_capture(h->s), p, max, timeout_ms);
}

JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeUidDeliver(JNIEnv *env, jclass cls,
                                                                              jlong handle,
                                                                              jobject buf, jint n)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    void *p = (*env)->GetDirectBufferAddress(env, buf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, buf);
    if (!h || !p || (jlong)n * (jlong)sizeof(mpc_uid_resolution) > cap)
        return -1;
    return mpc_capture_uid_deliver(mpc_session_capture(h->s), p, n);
}

/* ~1 Hz: one context record (UTF-8 info text + JSON). Timestamped here, on the packet clock. */
JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeContext(JNIEnv *env, jclass cls,
                                                                           jlong handle, jint kind,
                                                                           jint seq, jbyteArray info,
                                                                           jbyteArray json)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    if (!h || !json)
        return -1;
    jsize il = info ? (*env)->GetArrayLength(env, info) : 0;
    jsize jl = (*env)->GetArrayLength(env, json);
    jbyte *ip = il ? (*env)->GetByteArrayElements(env, info, NULL) : NULL;
    jbyte *jp = (*env)->GetByteArrayElements(env, json, NULL);
    int rc = -1;
    if (jp && (il == 0 || ip))
        rc = mpc_capture_context(mpc_session_capture(h->s), kind, (uint32_t)seq, mpc_now_boottime_ns(),
                                 (const char *)ip, (size_t)il, (const uint8_t *)jp, (size_t)jl);
    if (ip)
        (*env)->ReleaseByteArrayElements(env, info, ip, JNI_ABORT);
    if (jp)
        (*env)->ReleaseByteArrayElements(env, json, jp, JNI_ABORT);
    return rc;
}

JNIEXPORT void JNICALL Java_dev_minipcap_capture_NativeCore_nativeWriterStall(JNIEnv *env, jclass cls,
                                                                               jlong handle, jint ms)
{
    handle_t *h = (handle_t *)(intptr_t)handle;
    if (h && ms > 0)
        mpc_capture_request_stall(mpc_session_capture(h->s), (uint32_t)ms);
}

JNIEXPORT jint JNICALL Java_dev_minipcap_capture_NativeCore_nativeRecordSizes(JNIEnv *env, jclass cls)
{
    /* Lets Kotlin assert the ByteBuffer record layout at runtime. */
    return (jint)((sizeof(mpc_uid_request) << 16) | sizeof(mpc_uid_resolution));
}
