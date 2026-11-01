#include "Il2cpp/Il2cpp.h"

#include <android/log.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <jni.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

#define AGENT_LOG_TAG "Il2cppDumpAgent"

namespace
{
    std::once_flag g_startOnce;

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

    bool makeDirs(const std::string &path)
    {
        std::string current;
        current.reserve(path.size());
        for (size_t i = 0; i < path.size(); ++i)
        {
            current.push_back(path[i]);
            if (path[i] == '/' && current.size() > 1)
            {
                if (mkdir(current.c_str(), 0775) != 0 && errno != EEXIST)
                    return false;
            }
        }
        if (mkdir(path.c_str(), 0775) != 0 && errno != EEXIST)
            return false;
        return true;
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

    void autoDumpThisProcess()
    {
        for (int i = 0; i < 120 && !isIl2cppLoadedInThisProcess(); ++i)
            sleep(1);

        if (!isIl2cppLoadedInThisProcess())
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG,
                                "libil2cpp.so never appeared in this process");
            return;
        }

        const std::string path = dumpCsPath();
        if (path.empty())
        {
            __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Could not resolve dump.cs path");
            return;
        }

        for (int i = 0; i < 30; ++i)
        {
            try
            {
                Il2cpp::Init();
                if (!Il2cpp::IsDumperReady())
                {
                    sleep(1);
                    continue;
                }
                if (!Il2cpp::EnsureAttached())
                {
                    sleep(1);
                    continue;
                }
                if (Il2cpp::Dump(path))
                {
                    __android_log_print(ANDROID_LOG_INFO, AGENT_LOG_TAG, "dump.cs written: %s", path.c_str());
                    return;
                }
            }
            catch (...)
            {
                __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Dump attempt failed");
            }
            sleep(1);
        }

        __android_log_print(ANDROID_LOG_ERROR, AGENT_LOG_TAG, "Auto dump failed: %s", path.c_str());
    }

    void startAutoDumpOnce()
    {
        std::call_once(g_startOnce, []() {
            std::thread(autoDumpThisProcess).detach();
        });
    }
} // namespace

extern "C" JNIEXPORT __attribute__((visibility("default"))) jint JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/)
{
    startAutoDumpOnce();
    return JNI_VERSION_1_6;
}

__attribute__((constructor)) static void onLibraryLoad()
{
    startAutoDumpOnce();
}
