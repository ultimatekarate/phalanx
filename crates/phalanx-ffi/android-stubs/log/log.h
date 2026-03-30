// Stub for AOSP-internal log/log.h
// The standalone NDK does not ship this header. fdk-aac-sys vendors AOSP
// source that includes it unconditionally. We provide no-op macros so the
// build succeeds without modifying vendored code.
//
// See: https://github.com/mstorsjo/fdk-aac/issues/124

#ifndef LOG_LOG_H_STUB
#define LOG_LOG_H_STUB

#define ALOG(...)       ((void)0)
#define ALOGV(...)      ((void)0)
#define ALOGD(...)      ((void)0)
#define ALOGI(...)      ((void)0)
#define ALOGW(...)      ((void)0)
#define ALOGE(...)      ((void)0)
#define LOG_ALWAYS_FATAL_IF(...)  ((void)0)

// AOSP error-reporting function used by security patches in fdk-aac.
// No-op outside the platform build — these are CVE audit breadcrumbs, not functional code.
static inline int android_errorWriteLog(int tag, const char* subTag) {
    (void)tag; (void)subTag;
    return 0;
}

#endif // LOG_LOG_H_STUB
