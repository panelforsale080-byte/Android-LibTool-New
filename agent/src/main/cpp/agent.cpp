#include "Il2cpp/Il2cpp.h"

#include <android/log.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <jni.h>
#include <pthread.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#define AGENT_LOG_TAG "Il2cppDumpAgent"

namespace
{
    bool isLibraryLoaded(const char *libraryName)
    {
        FILE *maps = std::fopen("/proc/self/maps", "r");
        if (!maps)
            return false;

        char line[512];
        bool found = false;
        while (std::fgets(line, sizeof(line), maps))
        {
            if (std::strstr(line, libraryName))
            {
                found = true;
                break;
            }
        }
        std::fclose(maps);
        return found;
    }

    void waitForLibrary(const char *libraryName, int maxSeconds)
    {
        for (int i = 0; i < maxSeconds && !isLibraryLoaded(libraryName); ++i)
            sleep(1);
    }

    std::string thisPackageName()
    {
        char packageName[256] = {};
        FILE *fp = std::fopen("/proc/self/cmdline", "r");
        if (fp)
        {
            std::fread(packageName, 1, sizeof(packageName) - 1, fp);
            std::fclose(fp);
        }
        return packageName;
    }

    void makeDirs(const std::string &path)
    {
        std::string current;
        current.reserve(path.size());
        for (size_t i = 0; i < path.size(); ++i)
        {
            current.push_back(path[i]);
            if (path[i] == '/' && current.size() > 1)
                mkdir(current.c_str(), 0775);
        }
        mkdir(path.c_str(), 0775);
    }

    std::string dumpCsPath()
    {
        const std::string package = thisPackageName();
        if (package.empty())
            return {};

        const std::string dir = "/storage/emulated/0/Android/data/" + package + "/files";
        makeDirs(dir);
        return dir + "/dump.cs";
    }

    bool waitUntilRuntimeReady(int maxSeconds)
    {
        for (int i = 0; i < maxSeconds; ++i)
        {
            Il2cpp::Init();
            if (Il2cpp::IsDumperReady() && Il2cpp::IsRuntimeReady())
                return true;
            sleep(1);
        }
        return false;
    }

    void *dump_thread(void *)
    {
        // Same startup path as original lib_main -> hack_thread:
        // do not block the host process, wait for render + IL2CPP, then work.
        usleep(100 * 1000);

        waitForLibrary("libEGL.so", 120);
        if (!isLibraryLoaded("libEGL.so"))
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "libEGL.so did not load");
            return nullptr;
        }

        std::string runtimeLib;
        for (int i = 0; i < 180; ++i)
        {
            runtimeLib = Il2cpp::GetRuntimeLibraryName();
            if (!runtimeLib.empty())
                break;
            sleep(1);
        }
        if (runtimeLib.empty())
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                                "No IL2CPP runtime library found (libil2cpp/liblogic/libcsharp or any /data/app .so with classes)");
            return nullptr;
        }
        __android_log_print(ANDROID_LOG_INFO, AGENT_LOG_TAG, "Using IL2CPP library: %s", runtimeLib.c_str());

        // Extra settle after the same point the original UI would start,
        // so Unity/IL2CPP domain and assemblies actually exist.
        sleep(5);

        if (!waitUntilRuntimeReady(60))
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                                "IL2CPP runtime never became ready; skip dump");
            return nullptr;
        }

        const std::string path = dumpCsPath();
        if (path.empty())
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Could not resolve dump.cs path");
            return nullptr;
        }

        try
        {
            if (!Il2cpp::EnsureAttached())
            {
                __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                                    "Skip dump: IL2CPP thread attach not ready");
                return nullptr;
            }

            const bool ok = Il2cpp::Dump(path);
            Il2cpp::Detach();

            if (ok)
                __android_log_print(ANDROID_LOG_INFO, AGENT_LOG_TAG, "dump.cs written: %s", path.c_str());
            else
                __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Dump failed: %s", path.c_str());
        }
        catch (...)
        {
            try
            {
                Il2cpp::Detach();
            }
            catch (...)
            {
            }
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                                "Dump aborted; host process left running");
        }
        return nullptr;
    }
} // namespace

extern "C" JNIEXPORT __attribute__((visibility("default"))) jint JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/)
{
    return JNI_VERSION_1_6;
}

__attribute__((constructor)) static void lib_main()
{
    pthread_t ptid;
    pthread_create(&ptid, nullptr, dump_thread, nullptr);
}
