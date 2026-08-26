#include "Tool/SoMonitorTrace.h"

#include "Frida/gumpp/runtime.hpp"

#define cs_open _frida_cs_open
#define cs_disasm _frida_cs_disasm
#define cs_free _frida_cs_free
#define cs_close _frida_cs_close
#define cs_option _frida_cs_option
#include "frida-gum.h"

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mutex>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace
{
    static constexpr uint64_t kDenseMaxModuleSize = 16u * 1024u * 1024u;

    struct FileExecSegment
    {
        uint64_t runtimeStart = 0;
        uint64_t runtimeEnd = 0;
        uint64_t fileOffset = 0;
    };

    std::mutex g_mutex;
    std::mutex g_followMutex;
    SoTraceModule g_module;
    std::string g_status;
    bool g_starting = false;
    std::atomic<bool> g_active{false};

    GumStalker *g_stalker = nullptr;
    GumStalkerTransformer *g_transformer = nullptr;
    std::set<GumThreadId> g_followedThreads;

    std::thread g_followerThread;
    std::atomic<bool> g_followerStop{false};

    std::vector<uint64_t> g_denseHits;
    std::vector<std::string> g_denseMnemonic;
    std::vector<uint8_t> g_denseIsInsn;

    struct SparseSlot
    {
        uint64_t offset = 0;
        uint64_t hits = 0;
        std::string mnemonic;
    };
    std::vector<SparseSlot> g_sparseSlots;
    bool g_useDense = true;

    std::atomic<uint64_t> g_totalExecutions{0};
    std::atomic<uint64_t> g_calloutFires{0};
    std::atomic<uint64_t> g_blocksInstrumented{0};

    static bool inExecRange(uint64_t address)
    {
        for (const SoTraceExecRange &range : g_module.execRanges)
        {
            if (address >= range.begin && address < range.end)
                return true;
        }
        return false;
    }

    static bool isInTargetModule(uint64_t pc)
    {
        return pc >= g_module.base && pc < g_module.base + g_module.size && inExecRange(pc);
    }

    static std::vector<FileExecSegment> loadExecSegmentsFromFile(const SoTraceModule &module)
    {
        std::vector<FileExecSegment> out;
        const int fd = open(module.path.c_str(), O_RDONLY);
        if (fd < 0)
            return out;

        ElfW(Ehdr) ehdr{};
        if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr)) ||
            std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_phoff == 0 || ehdr.e_phnum == 0)
        {
            close(fd);
            return out;
        }

        std::vector<ElfW(Phdr)> phdrs(ehdr.e_phnum);
        const size_t phSize = sizeof(ElfW(Phdr)) * ehdr.e_phnum;
        if (pread(fd, phdrs.data(), phSize, static_cast<off_t>(ehdr.e_phoff)) != static_cast<ssize_t>(phSize))
        {
            close(fd);
            return out;
        }
        close(fd);

        for (const ElfW(Phdr) &phdr : phdrs)
        {
            if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X) || phdr.p_memsz == 0)
                continue;
            FileExecSegment seg;
            seg.runtimeStart = module.base + phdr.p_vaddr;
            seg.runtimeEnd = seg.runtimeStart + phdr.p_memsz;
            seg.fileOffset = phdr.p_offset;
            out.push_back(seg);
        }
        return out;
    }

    static bool readAtRuntimeVa(const SoTraceModule &module, const std::vector<FileExecSegment> &segments,
                                uint64_t runtimeVa, uint8_t *buffer, size_t length)
    {
        for (const FileExecSegment &seg : segments)
        {
            if (runtimeVa < seg.runtimeStart || runtimeVa + length > seg.runtimeEnd)
                continue;
            const int fd = open(module.path.c_str(), O_RDONLY);
            if (fd < 0)
                return false;
            const uint64_t off = seg.fileOffset + (runtimeVa - seg.runtimeStart);
            const ssize_t got = pread(fd, buffer, length, static_cast<off_t>(off));
            close(fd);
            return got == static_cast<ssize_t>(length);
        }
        if (runtimeVa + length <= runtimeVa)
            return false;
        std::memcpy(buffer, reinterpret_cast<void *>(runtimeVa), length);
        return true;
    }

    static bool buildMnemonicTables(const SoTraceModule &module, std::string &err)
    {
        g_denseHits.clear();
        g_denseMnemonic.clear();
        g_denseIsInsn.clear();
        g_sparseSlots.clear();
        g_useDense = module.size <= kDenseMaxModuleSize;

        if (g_useDense)
        {
            const size_t slots = static_cast<size_t>((module.size + 3u) / 4u);
            g_denseHits.resize(slots, 0);
            g_denseMnemonic.resize(slots);
            g_denseIsInsn.resize(slots, 0);
        }

        csh handle = 0;
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        {
            err = "Capstone init failed";
            return false;
        }
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

        const auto segments = loadExecSegmentsFromFile(module);
        if (segments.empty())
        {
            cs_close(&handle);
            err = "No executable segments in " + module.name;
            return false;
        }

        std::unordered_map<uint64_t, std::string> insnMap;
        for (const FileExecSegment &seg : segments)
        {
            uint64_t cursor = seg.runtimeStart;
            while (cursor < seg.runtimeEnd)
            {
                uint8_t buffer[4096];
                const size_t chunk = std::min(sizeof(buffer), static_cast<size_t>(seg.runtimeEnd - cursor));
                if (!readAtRuntimeVa(module, segments, cursor, buffer, chunk))
                {
                    cursor += 4;
                    continue;
                }

                cs_insn *insn = nullptr;
                const size_t maxInsn = std::max<size_t>(1, chunk / 2);
                const size_t n = cs_disasm(handle, buffer, chunk, cursor, maxInsn, &insn);
                if (n == 0)
                {
                    cursor += 4;
                    continue;
                }

                for (size_t i = 0; i < n; ++i)
                {
                    const uint64_t off = insn[i].address - module.base;
                    std::string text = std::string(insn[i].mnemonic);
                    if (insn[i].op_str[0] != '\0')
                    {
                        text += ' ';
                        text += insn[i].op_str;
                    }
                    insnMap[off] = std::move(text);
                }
                cursor = insn[n - 1].address + insn[n - 1].size;
                cs_free(insn, n);
            }
        }
        cs_close(&handle);

        if (insnMap.empty())
        {
            err = "No instructions disassembled in " + module.name;
            return false;
        }

        if (g_useDense)
        {
            for (const auto &kv : insnMap)
            {
                const size_t slot = static_cast<size_t>(kv.first >> 2);
                if (slot >= g_denseMnemonic.size())
                    continue;
                g_denseMnemonic[slot] = kv.second;
                g_denseIsInsn[slot] = 1;
            }
        }
        else
        {
            g_sparseSlots.reserve(insnMap.size());
            for (auto &kv : insnMap)
            {
                SparseSlot slot;
                slot.offset = kv.first;
                slot.mnemonic = std::move(kv.second);
                g_sparseSlots.push_back(std::move(slot));
            }
            std::sort(g_sparseSlots.begin(), g_sparseSlots.end(),
                      [](const SparseSlot &a, const SparseSlot &b) { return a.offset < b.offset; });
        }

        err.clear();
        return true;
    }

    static void incrementHit(uint64_t offset)
    {
        if (g_useDense)
        {
            const size_t slot = static_cast<size_t>(offset >> 2);
            if (slot < g_denseHits.size())
            {
                __atomic_fetch_add(&g_denseHits[slot], 1ULL, __ATOMIC_RELAXED);
                g_totalExecutions.fetch_add(1, std::memory_order_relaxed);
            }
        }
        else
        {
            size_t lo = 0;
            size_t hi = g_sparseSlots.size();
            while (lo < hi)
            {
                const size_t mid = lo + (hi - lo) / 2;
                if (g_sparseSlots[mid].offset < offset)
                    lo = mid + 1;
                else
                    hi = mid;
            }
            if (lo < g_sparseSlots.size() && g_sparseSlots[lo].offset == offset)
            {
                __atomic_fetch_add(&g_sparseSlots[lo].hits, 1ULL, __ATOMIC_RELAXED);
                g_totalExecutions.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    static void onInsnCallout(GumCpuContext *cpu_context, gpointer /*user_data*/)
    {
        g_calloutFires.fetch_add(1, std::memory_order_relaxed);
        const uint64_t pc = cpu_context->pc;
        if (!isInTargetModule(pc))
            return;
        incrementHit(pc - g_module.base);
    }

    static void transformBlock(GumStalkerIterator *iterator, GumStalkerWriter * /*output*/, gpointer /*user_data*/)
    {
        const cs_insn *insn = nullptr;
        bool inTarget = false;
        bool decided = false;

        while (gum_stalker_iterator_next(iterator, &insn))
        {
            if (!decided && insn)
            {
                inTarget = isInTargetModule(static_cast<uint64_t>(insn->address));
                decided = true;
                if (inTarget)
                    g_blocksInstrumented.fetch_add(1, std::memory_order_relaxed);
            }

            if (inTarget)
                gum_stalker_iterator_put_callout(iterator, onInsnCallout, nullptr, nullptr);
            gum_stalker_iterator_keep(iterator);
        }
    }

    static void followThread(GumThreadId threadId)
    {
        if (!g_stalker || !g_transformer || !g_active.load(std::memory_order_relaxed))
            return;
        std::lock_guard<std::mutex> lock(g_followMutex);
        if (g_followedThreads.count(threadId))
            return;
        gum_stalker_follow(g_stalker, threadId, g_transformer, nullptr);
        g_followedThreads.insert(threadId);
    }

    static gboolean enumerateFollowThread(const GumThreadDetails *details, gpointer /*user_data*/)
    {
        followThread(details->id);
        return TRUE;
    }

    static void followAllThreads()
    {
        gum_process_enumerate_threads(enumerateFollowThread, nullptr);
    }

    static void excludeHeavyModules(GumStalker *stalker)
    {
        gum_process_enumerate_modules(
            [](const GumModuleDetails *details, gpointer user_data) -> gboolean
            {
                auto *s = static_cast<GumStalker *>(user_data);
                if (!details->range || !details->name)
                    return TRUE;

                const std::string name = details->name;
                const std::string path = details->path ? details->path : "";

                // Exclude our inject + Frida runtime only — never exclude the target lib.
                const bool isOwnInject = name.find("libTool") != std::string::npos ||
                                         path.find("libTool") != std::string::npos ||
                                         name.find("libsupport") != std::string::npos;

                if (isOwnInject)
                    gum_stalker_exclude(s, details->range);
                return TRUE;
            },
            stalker);
    }

    static void followerMaintenanceLoop()
    {
        Gum::Runtime::ref();
        while (!g_followerStop.load(std::memory_order_relaxed))
        {
            if (g_active.load(std::memory_order_relaxed))
            {
                followAllThreads();
                if (g_stalker)
                    gum_stalker_flush(g_stalker);
            }
            usleep(500000);
        }
    }

    static void stopTrace()
    {
        g_active.store(false, std::memory_order_release);
        g_followerStop.store(true, std::memory_order_release);

        if (g_followerThread.joinable())
        {
            g_followerThread.join();
            g_followerThread = std::thread();
        }
        g_followerStop.store(false, std::memory_order_release);

        if (g_stalker)
        {
            std::lock_guard<std::mutex> lock(g_followMutex);
            for (GumThreadId tid : g_followedThreads)
                gum_stalker_unfollow(g_stalker, tid);
            g_followedThreads.clear();
            gum_stalker_flush(g_stalker);
        }

        if (g_transformer)
        {
            g_object_unref(g_transformer);
            g_transformer = nullptr;
        }
        if (g_stalker)
        {
            g_object_unref(g_stalker);
            g_stalker = nullptr;
        }
    }

    static std::string resolveAppPath(const std::string &raw, std::string &err)
    {
        const char *candidates[] = {
            "/sdcard/Android/data/com.android.support/files",
            "/sdcard/Download",
            "/data/local/tmp",
            "/data/data/com.android.support/files",
        };
        std::string root;
        for (const char *c : candidates)
        {
            if (::access(c, W_OK) == 0 || ::access(c, F_OK) == 0)
            {
                root = c;
                break;
            }
        }
        if (root.empty())
            root = candidates[0];
        ::mkdir(root.c_str(), 0777);

        std::string rel = raw;
        const size_t slash = rel.find_last_of('/');
        if (slash != std::string::npos)
            rel = rel.substr(slash + 1);
        for (char &c : rel)
        {
            if (c == ' ' || c == '\t' || c == '\n')
                c = '_';
        }
        if (rel.empty())
        {
            err = "Empty file name";
            return "";
        }
        const std::string full = root + "/" + rel;
        const size_t lastSlash = full.find_last_of('/');
        const std::string parent = full.substr(0, lastSlash);
        if (::access(parent.c_str(), W_OK) != 0)
        {
            err = "Folder not writable: " + parent;
            return "";
        }
        return full;
    }

    static void startTraceThread(SoTraceModule module)
    {
        stopTrace();

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = true;
            g_module = std::move(module);
            g_status = "Building instruction map for " + g_module.name + " ...";
            g_totalExecutions.store(0, std::memory_order_relaxed);
            g_calloutFires.store(0, std::memory_order_relaxed);
            g_blocksInstrumented.store(0, std::memory_order_relaxed);
        }

        if (!gum_stalker_is_supported())
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            g_status = "Stalker not supported on this device.";
            return;
        }

        std::string err;
        if (!buildMnemonicTables(g_module, err))
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            g_status = err.empty() ? "Failed to build instruction map." : err;
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_status = "Starting full Stalker trace on all threads ...";
        }

        Gum::Runtime::ref();

        g_stalker = gum_stalker_new();
        g_transformer = gum_stalker_transformer_make_from_callback(transformBlock, nullptr, nullptr);
        // -1 = never trust compiled blocks; always keep per-instruction callouts.
        gum_stalker_set_trust_threshold(g_stalker, -1);
        excludeHeavyModules(g_stalker);
        followAllThreads();
        gum_stalker_flush(g_stalker);

        g_active.store(true, std::memory_order_release);
        g_followerThread = std::thread(followerMaintenanceLoop);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            const size_t slots = g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size();
            size_t threadCount = 0;
            {
                std::lock_guard<std::mutex> followLock(g_followMutex);
                threadCount = g_followedThreads.size();
            }
            g_status = "Full runtime trace: " + g_module.name + " [" + std::to_string(threadCount) +
                       " threads, " + std::to_string(slots) +
                       " insn slots]. Every executed insn (sub/sp/str/...) counted — no time limit.";
        }
    }
} // namespace

namespace SoMonitorTrace
{
    void Start(const SoTraceModule &module)
    {
        std::thread([module]() { startTraceThread(module); }).detach();
    }

    void Stop()
    {
        stopTrace();
        std::lock_guard<std::mutex> lock(g_mutex);
        g_starting = false;
        g_status = "Runtime trace stopped.";
    }

    SoTraceState GetState()
    {
        SoTraceState state;
        std::lock_guard<std::mutex> lock(g_mutex);
        state.active = g_active.load(std::memory_order_relaxed);
        state.starting = g_starting;
        state.status = g_status;
        state.moduleName = g_module.name;
        state.base = g_module.base;
        {
            std::lock_guard<std::mutex> followLock(g_followMutex);
            state.threadCount = g_followedThreads.size();
        }
        state.insnSlots = g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size();
        state.totalExecutions = g_totalExecutions.load(std::memory_order_relaxed);
        state.calloutFires = g_calloutFires.load(std::memory_order_relaxed);
        state.blocksInstrumented = g_blocksInstrumented.load(std::memory_order_relaxed);
        state.stalkerSupported = gum_stalker_is_supported();
        return state;
    }

    std::vector<SoTraceHitEntry> GetSnapshot(bool hideZeroHits, uint64_t minHits, bool sortByHitsDesc)
    {
        std::vector<SoTraceHitEntry> out;
        std::lock_guard<std::mutex> lock(g_mutex);

        if (g_useDense)
        {
            out.reserve(g_denseMnemonic.size() / 8);
            for (size_t slot = 0; slot < g_denseMnemonic.size(); ++slot)
            {
                const uint64_t hits = __atomic_load_n(&g_denseHits[slot], __ATOMIC_RELAXED);
                if (hideZeroHits && hits == 0)
                    continue;
                if (hits < minHits)
                    continue;
                if (!g_denseIsInsn[slot] && hits == 0)
                    continue;
                SoTraceHitEntry entry;
                entry.offset = static_cast<uint64_t>(slot) << 2;
                entry.mnemonic = g_denseIsInsn[slot] ? g_denseMnemonic[slot] : "???";
                entry.hits = hits;
                out.push_back(std::move(entry));
            }
        }
        else
        {
            out.reserve(g_sparseSlots.size());
            for (const SparseSlot &slot : g_sparseSlots)
            {
                const uint64_t hits = __atomic_load_n(&const_cast<SparseSlot &>(slot).hits, __ATOMIC_RELAXED);
                if (hideZeroHits && hits == 0)
                    continue;
                if (hits < minHits)
                    continue;
                SoTraceHitEntry entry;
                entry.offset = slot.offset;
                entry.mnemonic = slot.mnemonic;
                entry.hits = hits;
                out.push_back(std::move(entry));
            }
        }

        if (sortByHitsDesc)
        {
            std::sort(out.begin(), out.end(), [](const SoTraceHitEntry &a, const SoTraceHitEntry &b)
                      {
                          if (a.hits != b.hits)
                              return a.hits > b.hits;
                          return a.offset < b.offset;
                      });
        }
        else
        {
            std::sort(out.begin(), out.end(),
                      [](const SoTraceHitEntry &a, const SoTraceHitEntry &b) { return a.offset < b.offset; });
        }
        return out;
    }

    void ClearHits()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_useDense)
        {
            for (size_t slot = 0; slot < g_denseHits.size(); ++slot)
                __atomic_store_n(&g_denseHits[slot], 0ULL, __ATOMIC_RELAXED);
        }
        else
        {
            for (SparseSlot &slot : g_sparseSlots)
                __atomic_store_n(&slot.hits, 0ULL, __ATOMIC_RELAXED);
        }
        g_totalExecutions.store(0, std::memory_order_relaxed);
        g_calloutFires.store(0, std::memory_order_relaxed);
    }

    bool ExportCsv(const std::string &fileName, std::string &outPath)
    {
        std::string moduleName;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            moduleName = g_module.name;
        }
        const std::vector<SoTraceHitEntry> rows = GetSnapshot(false, 0, true);

        std::string err;
        const std::string full = resolveAppPath(fileName, err);
        if (full.empty())
        {
            outPath = err;
            return false;
        }

        FILE *f = fopen(full.c_str(), "w");
        if (!f)
        {
            outPath = "Cannot open " + full;
            return false;
        }

        std::fprintf(f, "# Axcel Modified tools - full runtime instruction trace for %s\n", moduleName.c_str());
        std::fprintf(f, "offset,mnemonic,hits\n");
        for (const SoTraceHitEntry &row : rows)
        {
            std::fprintf(f, "0x%08" PRIX64 ",\"%s\",%" PRIu64 "\n", row.offset, row.mnemonic.c_str(), row.hits);
        }
        fclose(f);

        char absBuf[PATH_MAX] = {};
        if (realpath(full.c_str(), absBuf))
            outPath = absBuf;
        else
            outPath = full;
        outPath += " (" + std::to_string(rows.size()) + " rows)";
        return true;
    }
} // namespace SoMonitorTrace
