#include <jni.h>
#include <string>
#include <unistd.h>

extern "C" JNIEXPORT jstring JNICALL
Java_com_arophix_decompileapk_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    
    int length = strlen("Arophix Frida Hooking Example."); // length = 30
    
    
    char buf[10] = {0,1,2,3,45,5,6,7,8,9};
    int r = read(0, buf, 10);
    
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}
