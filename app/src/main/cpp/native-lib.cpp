#include <jni.h>
#include <string>
#include <unistd.h>
#include <android/log.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_arophix_decompileapk_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    
    int length = strlen("Arophix Frida Hooking Example."); // length = 30
    
    __android_log_print(ANDROID_LOG_INFO, "Arophix", "length: %d", length);
    
    char buf[10] = {6,5,9,2,0,1,4,7,6,33};
    int r = read(0, buf, 10);
    
    __android_log_print(ANDROID_LOG_INFO, "Arophix", "Returned value of read(): %d", r);
    
    std::string hello = "Hello from C++";
    
    return env->NewStringUTF(hello.c_str());
}
