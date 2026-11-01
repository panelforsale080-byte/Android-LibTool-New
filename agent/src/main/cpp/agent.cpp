#include "Il2cpp/Il2cpp.h"

#include <android/log.h>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <jni.h>
#include <pthread.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#define AGENT_LOG_TAG "Il2cppDumpAgent"

namespace
{
    std::string g_filesDir;
    std::string g_logPath;

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

    bool canWriteDir(const std::string &dir)
    {
        makeDirs(dir);
        const std::string probe = dir + "/.dump_write_probe";
        FILE *fp = std::fopen(probe.c_str(), "w");
        if (!fp)
            return false;
        std::fclose(fp);
        std::remove(probe.c_str());
        return true;
    }

    std::string chooseFilesDir()
    {
        const std::string package = thisPackageName();
        std::vector<std::string> candidates;
        if (!package.empty())
        {
            candidates.push_back("/storage/emulated/0/Android/data/" + package + "/files");
            candidates.push_back("/sdcard/Android/data/" + package + "/files");
            candidates.push_back("/data/data/" + package + "/files");
            candidates.push_back("/data/user/0/" + package + "/files");
        }
        candidates.push_back("/storage/emulated/0/Download");
        candidates.push_back("/sdcard/Download");

        for (const auto &dir : candidates)
        {
            if (canWriteDir(dir))
                return dir;
        }
        return {};
    }

    void logf(const char *fmt, ...)
    {
        char message[1024];
        va_list args;
        va_start(args, fmt);
        std::vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);

        __android_log_print(ANDROID_LOG_INFO, AGENT_LOG_TAG, "%s", message);

        if (g_logPath.empty())
            return;

        FILE *fp = std::fopen(g_logPath.c_str(), "a");
        if (!fp)
            return;
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        std::fprintf(fp, "[%lld] %s\n", static_cast<long long>(now), message);
        std::fclose(fp);
    }

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

    bool graphicsReady()
    {
        return isLibraryLoaded("libEGL.so") || isLibraryLoaded("libvulkan.so") ||
               isLibraryLoaded("libunity.so") || isLibraryLoaded("libmain.so");
    }

    bool waitUntilRuntimeReady(int maxSeconds)
    {
        for (int i = 0; i < maxSeconds; ++i)
        {
            Il2cpp::Init();
            const bool dumper = Il2cpp::IsDumperReady();
            const bool runtime = Il2cpp::IsRuntimeReady();
            if (i == 0 || i % 5 == 0 || (dumper && runtime))
            {
                logf("ready-check %d/%d dumper=%d runtime=%d lib=%s", i + 1, maxSeconds,
                     dumper ? 1 : 0, runtime ? 1 : 0, Il2cpp::GetRuntimeLibraryName().c_str());
            }
            if (dumper && runtime)
                return true;
            sleep(1);
        }
        return false;
    }

    void *dump_thread(void *)
    {
        usleep(100 * 1000);

        const std::string package = thisPackageName();
        g_filesDir = chooseFilesDir();
        if (!g_filesDir.empty())
            g_logPath = g_filesDir + "/log.txt";

        logf("dump thread start pid=%d package=%s", getpid(), package.c_str());
        logf("files dir=%s", g_filesDir.empty() ? "(none)" : g_filesDir.c_str());
        logf("egl=%d vulkan=%d unity=%d main=%d", isLibraryLoaded("libEGL.so") ? 1 : 0,
             isLibraryLoaded("libvulkan.so") ? 1 : 0, isLibraryLoaded("libunity.so") ? 1 : 0,
             isLibraryLoaded("libmain.so") ? 1 : 0);

        for (int i = 0; i < 120 && !graphicsReady(); ++i)
            sleep(1);
        logf("graphics ready=%d egl=%d vulkan=%d", graphicsReady() ? 1 : 0,
             isLibraryLoaded("libEGL.so") ? 1 : 0, isLibraryLoaded("libvulkan.so") ? 1 : 0);

        std::string runtimeLib;
        for (int i = 0; i < 180; ++i)
        {
            runtimeLib = Il2cpp::GetRuntimeLibraryName();
            if (!runtimeLib.empty())
                break;
            if (i == 0 || i % 10 == 0)
                logf("waiting for IL2CPP library %ds", i);
            sleep(1);
        }
        if (runtimeLib.empty())
        {
            logf("ERROR: no IL2CPP library found (libil2cpp/liblogic/libcsharp or any app .so with il2cpp_domain_get)");
            return nullptr;
        }
        logf("using IL2CPP library: %s", runtimeLib.c_str());

        sleep(5);

        if (!waitUntilRuntimeReady(90))
        {
            logf("ERROR: IL2CPP runtime never became ready; skip dump");
            return nullptr;
        }

        if (g_filesDir.empty())
        {
            g_filesDir = chooseFilesDir();
            if (!g_filesDir.empty())
                g_logPath = g_filesDir + "/log.txt";
        }
        if (g_filesDir.empty())
        {
            logf("ERROR: no writable files directory");
            return nullptr;
        }

        const std::string dumpPath = g_filesDir + "/dump.cs";
        logf("dump path=%s", dumpPath.c_str());

        try
        {
            if (!Il2cpp::EnsureAttached())
            {
                logf("ERROR: EnsureAttached failed");
                return nullptr;
            }
            logf("attached, starting dump");

            const bool ok = Il2cpp::Dump(dumpPath);
            Il2cpp::Detach();

            if (ok)
            {
                std::ifstream in(dumpPath, std::ios::ate | std::ios::binary);
                const auto size = in ? static_cast<long>(in.tellg()) : -1L;
                logf("SUCCESS dump.cs written size=%ld", size);
            }
            else
            {
                logf("ERROR: Dump() returned false for %s errno=%d", dumpPath.c_str(), errno);
            }
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
            logf("ERROR: dump exception, host process left running");
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
