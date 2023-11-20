#include <jni.h>
#include <string>
#include "chook.h"
#include "android/log.h"

int ProxyPthreadCreate(pthread_t *__pthread_ptr, pthread_attr_t const *__attr,
                       void *(*__start_routine)(void *), void *__args) {
    __android_log_print(ANDROID_LOG_ERROR, "TAG", "监听到线程的创建");
    return pthread_create(__pthread_ptr, __attr, __start_routine, __args);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_cnting_nativehookstudy_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";

    chook("libart.so", "pthread_create", (void *) ProxyPthreadCreate);
    return env->NewStringUTF(hello.c_str());
}}