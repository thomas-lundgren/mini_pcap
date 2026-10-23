/* JNI bridge. Called only at session start/stop, for ~1 Hz counter snapshots and
 * clock pairs, and for batched new-flow announcements through a direct ByteBuffer.
 * Nothing here runs per packet. */
#include <errno.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <android/log.h>

#include "mpc/engine.h"

#define TAG "mpcnative"

typedef struct {
    mpc_session *s;
    char *pcap_path;
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

JNIEXPORT jlong JNICALL Java_dev_minipcap_capture_NativeCore_nativeStart(JNIEnv *env, jclass cls, jint tun_fd,
                                                                         jstring pcap_path, jint snaplen,
                                                                         jint mtu, jint variant, jint ring_bytes)
{
    handle_t *h = calloc(1, sizeof(*h));
    if (!h) {
        close(tun_fd);
        return -ENOMEM;
    }
    h->pcap_path = dup_jstring(env, pcap_path);
    mpc_capture_config cfg = {
        .pcap_path = h->pcap_path,
        .snaplen = (uint32_t)snaplen, /* -1 -> MPC_SNAPLEN_HEADERS */
        .mtu = (uint32_t)mtu,
        .variant = variant,
        .ring_bytes = (size_t)ring_bytes,
    };
    int err = 0;
    h->s = mpc_session_start(tun_fd, &cfg, &err);
    if (!h->s) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "session start failed: %d", err);
        free(h->pcap_path);
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
    free(h->pcap_path);
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

/* CLOCK_BOOTTIME and CLOCK_REALTIME read back to back (ns): CLOCK_SYNC records. */
JNIEXPORT void JNICALL Java_dev_minipcap_capture_NativeCore_nativeClockPair(JNIEnv *env, jclass cls,
                                                                            jlongArray out)
{
    struct timespec b0, r, b1;
    clock_gettime(CLOCK_BOOTTIME, &b0);
    clock_gettime(CLOCK_REALTIME, &r);
    clock_gettime(CLOCK_BOOTTIME, &b1);
    jlong v[2];
    int64_t n0 = (int64_t)b0.tv_sec * 1000000000LL + b0.tv_nsec;
    int64_t n1 = (int64_t)b1.tv_sec * 1000000000LL + b1.tv_nsec;
    v[0] = n0 + (n1 - n0) / 2;
    v[1] = (int64_t)r.tv_sec * 1000000000LL + r.tv_nsec;
    (*env)->SetLongArrayRegion(env, out, 0, 2, v);
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
    return (jint)sizeof(mpc_uid_request);
}
