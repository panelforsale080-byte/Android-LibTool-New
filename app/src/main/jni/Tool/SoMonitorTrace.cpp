#include "Tool/SoMonitorTrace.h"

#include "Frida/gumpp/runtime.hpp"
#include "dobby.h"

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
#include <link.h>
#include <map>
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
    static constexpr size_t kMaxEntryHooks = 8192u;

    struct FileExecSegment
    {
        uint64_t runtimeStart = 0;
        uint64_t runtimeEnd = 0;
        uint64_t fileOffset = 0;
    };

    std::mutex g_mutex;
    SoTraceModule g_module;
    std::string g_status;
    bool g_starting = false;
    std::atomic<bool> g_active{false};

    std::thread g_samplerThread;
    std::vector<uint64_t> g_hookedRuntimeAddrs;

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
    std::atomic<uint64_t> g_sampleHits{0};
    std::atomic<uint64_t> g_hookHits{0};
    std::atomic<uint64_t> g_sampleRounds{0};
    std::atomic<size_t> g_lastThreadCount{0};

    thread_local bool t_inHook = false;

    static inline unsigned symType(unsigned char info) { return info & 0xf; }

    static bool inExecRange(uint64_t address)
    {
        for (const SoTraceExecRange &range : g_module.execRanges)
        {
            if (address >= range.begin && address < range.end)
                return true;
        }
        return false;
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

    static void collectDynsymRuntime(std::set<uint64_t> &out)
    {
        const int fd = open(g_module.path.c_str(), O_RDONLY);
        if (fd < 0)
            return;

        ElfW(Ehdr) ehdr{};
        if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr)) ||
            std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_shoff == 0 || ehdr.e_shnum == 0)
        {
            close(fd);
            return;
        }

        std::vector<ElfW(Shdr)> sections(ehdr.e_shnum);
        const size_t tableSize = sizeof(ElfW(Shdr)) * ehdr.e_shnum;
        if (pread(fd, sections.data(), tableSize, static_cast<off_t>(ehdr.e_shoff)) != static_cast<ssize_t>(tableSize))
        {
            close(fd);
            return;
        }

        const ElfW(Shdr) *dynsym = nullptr;
        for (size_t i = 0; i < sections.size(); ++i)
        {
            if (sections[i].sh_type == SHT_DYNSYM)
            {
                dynsym = &sections[i];
                break;
            }
        }
        if (!dynsym || dynsym->sh_entsize == 0 || dynsym->sh_size == 0)
        {
            close(fd);
            return;
        }

        const size_t symCount = dynsym->sh_size / dynsym->sh_entsize;
        std::vector<ElfW(Sym)> symbols(symCount);
        if (pread(fd, symbols.data(), dynsym->sh_size, static_cast<off_t>(dynsym->sh_offset)) !=
            static_cast<ssize_t>(dynsym->sh_size))
        {
            close(fd);
            return;
        }
        close(fd);

        for (const ElfW(Sym) &sym : symbols)
        {
            if (sym.st_value == 0 || sym.st_shndx == SHN_UNDEF)
                continue;
            const unsigned type = symType(sym.st_info);
            if (type != STT_FUNC && type != STT_NOTYPE)
                continue;
            const uint64_t runtime = g_module.base + sym.st_value;
            if (inExecRange(runtime))
                out.insert(runtime);
        }
    }

    static bool buildMnemonicTables(const SoTraceModule &module, std::set<uint64_t> &blTargets, std::string &err)
    {
        g_denseHits.clear();
        g_denseMnemonic.clear();
        g_denseIsInsn.clear();
        g_sparseSlots.clear();
        blTargets.clear();
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
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        const auto segments = loadExecSegmentsFromFile(module);
        if (segments.empty())
        {
            cs_close(&handle);
            err = "No executable segments in " + module.name;
            return false;
        }

        const uint64_t moduleEnd = module.base + module.size;
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
                    insnMap[off] = text;

                    const char *mn = insn[i].mnemonic;
                    if ((std::strcmp(mn, "bl") == 0 || std::strcmp(mn, "blr") == 0) && insn[i].detail &&
                        insn[i].detail->arm64.op_count > 0)
                    {
                        const cs_arm64_op &op = insn[i].detail->arm64.operands[0];
                        if (op.type == ARM64_OP_IMM)
                        {
                            const uint64_t target = static_cast<uint64_t>(op.imm);
                            if (target >= module.base && target < moduleEnd && inExecRange(target))
                                blTargets.insert(target);
                        }
                    }
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

    static void recordPc(uint64_t pc)
    {
        if (pc < g_module.base || pc >= g_module.base + g_module.size)
            return;
        if (!inExecRange(pc))
            return;
        incrementHit(pc - g_module.base);
        g_sampleHits.fetch_add(1, std::memory_order_relaxed);
    }

    static void onEntryInstrument(void *address, DobbyRegisterContext * /*ctx*/)
    {
        if (!g_active.load(std::memory_order_relaxed) || t_inHook)
            return;
        t_inHook = true;
        const uint64_t runtime = reinterpret_cast<uint64_t>(address);
        if (runtime >= g_module.base && runtime < g_module.base + g_module.size)
        {
            incrementHit(runtime - g_module.base);
            g_hookHits.fetch_add(1, std::memory_order_relaxed);
        }
        t_inHook = false;
    }

    static void sampleThreadContext(GumThreadId /*thread_id*/, GumCpuContext *cpu_context, gpointer /*user_data*/)
    {
        if (!g_active.load(std::memory_order_relaxed))
            return;
        recordPc(cpu_context->pc);
    }

    static void samplerLoop()
    {
        Gum::Runtime::ref();
        while (g_active.load(std::memory_order_relaxed))
        {
            size_t count = 0;
            gum_process_enumerate_threads(
                [](const GumThreadDetails *details, gpointer user_data) -> gboolean
                {
                    auto *n = static_cast<size_t *>(user_data);
                    gum_process_modify_thread(details->id, sampleThreadContext, nullptr);
                    ++(*n);
                    return TRUE;
                },
                &count);
            g_lastThreadCount.store(count, std::memory_order_relaxed);
            g_sampleRounds.fetch_add(1, std::memory_order_relaxed);
            usleep(500);
        }
    }

    static size_t installEntryHooks(const std::set<uint64_t> &dynsym, const std::set<uint64_t> &blTargets)
    {
        std::set<uint64_t> merged = dynsym;
        merged.insert(blTargets.begin(), blTargets.end());

        g_hookedRuntimeAddrs.clear();
        if (merged.empty())
            return 0;

        dobby_enable_near_branch_trampoline();
        size_t failed = 0;
        for (const uint64_t runtime : merged)
        {
            if (g_hookedRuntimeAddrs.size() >= kMaxEntryHooks)
                break;
            if (DobbyInstrument(reinterpret_cast<void *>(runtime), onEntryInstrument) == 0)
                g_hookedRuntimeAddrs.push_back(runtime);
            else
                ++failed;
        }
        dobby_disable_near_branch_trampoline();
        (void)failed;
        return g_hookedRuntimeAddrs.size();
    }

    static void removeEntryHooks()
    {
        for (const uint64_t runtime : g_hookedRuntimeAddrs)
            DobbyDestroy(reinterpret_cast<void *>(runtime));
        g_hookedRuntimeAddrs.clear();
    }


    static void removeEntryHooks()(const std::string &raw, std::string &err)
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
        std::thread oldSampler;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_active.store(false, std::memory_order_release);
            if (g_samplerThread.joinable())
                oldSampler = std::move(g_samplerThread);
            removeEntryHooks();
            g_starting = true;
            g_module = std::move(module);
            g_status = "Building instruction map for " + g_module.name + " ...";
            g_totalExecutions.store(0, std::memory_order_relaxed);
            g_sampleHits.store(0, std::memory_order_relaxed);
            g_hookHits.store(0, std::memory_order_relaxed);
            g_sampleRounds.store(0, std::memory_order_relaxed);
        }
        if (oldSampler.joinable())
            oldSampler.join();

        std::set<uint64_t> blTargets;
        std::string err;
        if (!buildMnemonicTables(g_module, blTargets, err))
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            g_status = err.empty() ? "Failed to build instruction map." : err;
            return;
        }

        std::set<uint64_t> dynsym;
        collectDynsymRuntime(dynsym);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_status = "Installing PC sampler + entry hooks ...";
        }

        const size_t hookCount = installEntryHooks(dynsym, blTargets);

        g_active.store(true, std::memory_order_release);
        g_samplerThread = std::thread(samplerLoop);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            const size_t slots = g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size();
            g_status = "Tracing " + g_module.name + " [PC sampler + " + std::to_string(hookCount) +
                       " entry hooks, " + std::to_string(slots) +
                       " slots]. Play the game — hits update live.";
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
        std::thread oldSampler;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_active.store(false, std::memory_order_release);
            if (g_samplerThread.joinable())
                oldSampler = std::move(g_samplerThread);
            removeEntryHooks();
            g_starting = false;
            g_status = "Runtime trace stopped.";
        }
        if (oldSampler.joinable())
            oldSampler.join();
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
        state.threadCount = g_lastThreadCount.load(std::memory_order_relaxed);
        state.insnSlots = g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size();
        state.totalExecutions = g_totalExecutions.load(std::memory_order_relaxed);
        state.sampleHits = g_sampleHits.load(std::memory_order_relaxed);
        state.hookHits = g_hookHits.load(std::memory_order_relaxed);
        state.sampleRounds = g_sampleRounds.load(std::memory_order_relaxed);
        state.hookedCount = g_hookedRuntimeAddrs.size();
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
        g_sampleHits.store(0, std::memory_order_relaxed);
        g_hookHits.store(0, std::memory_order_relaxed);
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

        std::fprintf(f, "# Axcel Modified tools - runtime instruction trace for %s\n", moduleName.c_str());
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
