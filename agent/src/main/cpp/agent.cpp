#include "Il2cpp/Il2cpp.h"

#include <android/log.h>
#include <cstdio>
#include <cstring>
#include <jni.h>
#include <string>

#define AGENT_LOG_TAG "Il2cppDumpAgent"

namespace
{
    bool isIl2cppLoadedInThisProcess()
    {
        FILE *maps = std::fopen("/proc/self/maps", "r");
        if (!maps)
            return false;

        char line[512];
        bool found = false;
        while (std::fgets(line, sizeof(line), maps))
        {
            if (std::strstr(line, "libil2cpp.so"))
            {
                found = true;
                break;
            }
        }
        std::fclose(maps);
        return found;
    }

    jstring jniMessage(JNIEnv *env, const std::string &message)
    {
        return env->NewStringUTF(message.c_str());
    }
} // namespace

extern "C" JNIEXPORT __attribute__((visibility("default"))) jstring JNICALL
Java_com_example_il2cppagent_DumpAgent_nativeDump(JNIEnv *env, jclass /*clazz*/, jstring outputPath)
{
    if (!env || !outputPath)
        return jniMessage(env, "Dump failed: missing JNI environment or output path.");

    const char *pathChars = env->GetStringUTFChars(outputPath, nullptr);
    if (!pathChars)
        return jniMessage(env, "Dump failed: could not read the output path.");

    const std::string path(pathChars);
    env->ReleaseStringUTFChars(outputPath, pathChars);

    if (path.empty())
        return jniMessage(env, "Dump failed: empty output path.");

    if (!isIl2cppLoadedInThisProcess())
    {
        __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                            "libil2cpp.so is not loaded in this process");
        return jniMessage(env, "Dump failed: libil2cpp.so is not loaded in this process. "
                               "Call DumpAgent after Unity/IL2CPP has initialized.");
    }

    try
    {
        Il2cpp::Init();
        if (!Il2cpp::IsDumperReady())
        {
            return jniMessage(env, "Dump failed: IL2CPP APIs are not ready. "
                                   "Load this library after Unity/IL2CPP has initialized.");
        }

        if (!Il2cpp::EnsureAttached())
        {
            return jniMessage(env, "Dump failed: could not attach this thread to the IL2CPP domain.");
        }

        const bool ok = Il2cpp::Dump(path);
        if (!ok)
        {
            return jniMessage(env, "Dump failed while writing dump.cs: " + path);
        }

        __android_log_print(ANDROID_LOG_INFO, AGENT_LOG_TAG, "Dump succeeded: %s", path.c_str());
        return jniMessage(env, "Dump succeeded: " + path);
    }
    catch (const std::exception &ex)
    {
        __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Dump exception: %s", ex.what());
        return jniMessage(env, std::string("Dump failed: ") + ex.what());
    }
    catch (...)
    {
        __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Dump failed with an unexpected exception");
        return jniMessage(env, "Dump failed: unexpected exception.");
    }
}
