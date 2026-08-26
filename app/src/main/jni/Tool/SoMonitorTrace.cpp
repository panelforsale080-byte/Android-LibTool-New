#include "Tool/SoMonitorTrace.h"

#include "Frida/gumpp/gumpp.hpp"
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
#include <mutex>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    // Dense mnemonic table only for libs <= 4 MB. Larger libs use lazy hit maps.
    static constexpr uint64_t kDenseMaxModuleSize = 4u * 1024u * 1024u;
    static constexpr uint64_t kPrologueScanMaxSize = 4u * 1024u * 1024u;
    static constexpr size_t kHookBatchSize = 48;

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
    std::atomic<bool> g_cancelInstall{false};
    std::atomic<bool> g_hookInstalling{false};

    std::thread g_samplerThread;
    std::vector<uint64_t> g_interceptorAddrs;
    std::vector<uint64_t> g_dobbyAddrs;
    std::unordered_set<uint64_t> g_hookedSet;

    Gum::RefPtr<Gum::Interceptor> g_interceptor;
    std::unique_ptr<Gum::InvocationListener> g_entryListener;

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
    bool g_lazyMode = false;

    std::unordered_map<uint64_t, uint64_t> g_lazyHits;
    std::unordered_map<uint64_t, std::string> g_lazyMnemonic;

    std::atomic<uint64_t> g_totalExecutions{0};
    std::atomic<uint64_t> g_sampleHits{0};
    std::atomic<uint64_t> g_hookHits{0};
    std::atomic<uint64_t> g_sampleRounds{0};
    std::atomic<size_t> g_lastThreadCount{0};
    std::atomic<size_t> g_hookFailed{0};
    std::atomic<size_t> g_hookInstallDone{0};
    std::atomic<size_t> g_hookInstallTotal{0};
    std::atomic<size_t> g_hookCap{0};

    thread_local bool t_inHook = false;

    static size_t hookCapForModule(uint64_t size)
    {
        if (size <= 2u * 1024u * 1024u)
            return 8192;
        if (size <= 6u * 1024u * 1024u)
            return 3072;
        if (size <= 12u * 1024u * 1024u)
            return 1536;
        return 768;
    }

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

    static void incrementHit(uint64_t offset);

    class NativeEntryListener : public Gum::InvocationListener
    {
      public:
        void on_enter(Gum::InvocationContext *context) override
        {
            if (!g_active.load(std::memory_order_relaxed))
                return;
            void *func = context->get_function();
            if (!func)
                return;
            const uint64_t runtime = reinterpret_cast<uint64_t>(func);
            if (runtime < g_module.base || runtime >= g_module.base + g_module.size)
                return;
            if (!inExecRange(runtime))
                return;
            incrementHit(runtime - g_module.base);
            g_hookHits.fetch_add(1, std::memory_order_relaxed);
        }

        void on_leave(Gum::InvocationContext * /*context*/) override {}
    };

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

    static std::string disasmOneRuntime(uint64_t runtime, const std::vector<FileExecSegment> &segments)
    {
        uint8_t buffer[16]{};
        if (!readAtRuntimeVa(g_module, segments, runtime, buffer, sizeof(buffer)))
            return "???";

        csh handle = 0;
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
            return "???";

        cs_insn *insn = nullptr;
        const size_t n = cs_disasm(handle, buffer, sizeof(buffer), runtime, 1, &insn);
        std::string text = "???";
        if (n > 0)
        {
            text = insn[0].mnemonic;
            if (insn[0].op_str[0] != '\0')
            {
                text += ' ';
                text += insn[0].op_str;
            }
            cs_free(insn, n);
        }
        cs_close(&handle);
        return text;
    }

    static void rememberMnemonic(uint64_t offset, const std::string &text)
    {
        if (g_lazyMode)
        {
            g_lazyMnemonic[offset] = text;
            return;
        }
        if (g_useDense)
        {
            const size_t slot = static_cast<size_t>(offset >> 2);
            if (slot < g_denseMnemonic.size())
            {
                g_denseMnemonic[slot] = text;
                g_denseIsInsn[slot] = 1;
            }
        }
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

    static bool scanHookTargets(const SoTraceModule &module, const std::vector<FileExecSegment> &segments,
                                std::set<uint64_t> &blTargets, std::set<uint64_t> &prologueTargets,
                                std::unordered_map<uint64_t, std::string> *fullInsnMap, std::string &err)
    {
        blTargets.clear();
        prologueTargets.clear();

        csh handle = 0;
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        {
            err = "Capstone init failed";
            return false;
        }

        const bool needDetail = true;
        cs_option(handle, CS_OPT_DETAIL, needDetail ? CS_OPT_ON : CS_OPT_OFF);

        const uint64_t moduleEnd = module.base + module.size;
        const bool scanPrologue = module.size <= kPrologueScanMaxSize;
        size_t insnSeen = 0;

        for (const FileExecSegment &seg : segments)
        {
            uint64_t cursor = seg.runtimeStart;
            while (cursor < seg.runtimeEnd)
            {
                if (g_cancelInstall.load(std::memory_order_relaxed))
                {
                    cs_close(&handle);
                    err = "Trace cancelled.";
                    return false;
                }

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
                    ++insnSeen;
                    const uint64_t off = insn[i].address - module.base;
                    const char *mn = insn[i].mnemonic;

                    if (fullInsnMap)
                    {
                        std::string text = std::string(mn);
                        if (insn[i].op_str[0] != '\0')
                        {
                            text += ' ';
                            text += insn[i].op_str;
                        }
                        (*fullInsnMap)[off] = std::move(text);
                    }
                    else if (scanPrologue)
                    {
                        if (std::strcmp(mn, "sub") == 0 && insn[i].op_str[0] == 's' && insn[i].op_str[1] == 'p')
                            prologueTargets.insert(insn[i].address);
                        else if (std::strncmp(mn, "stp", 3) == 0)
                            prologueTargets.insert(insn[i].address);
                        else if (std::strcmp(mn, "pacibsp") == 0)
                            prologueTargets.insert(insn[i].address);
                    }

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

        if (insnSeen == 0)
        {
            err = "No instructions disassembled in " + module.name;
            return false;
        }

        err.clear();
        return true;
    }

    static bool buildMnemonicTables(const SoTraceModule &module, std::set<uint64_t> &blTargets,
                                    std::set<uint64_t> &prologueTargets, std::string &err)
    {
        g_denseHits.clear();
        g_denseMnemonic.clear();
        g_denseIsInsn.clear();
        g_sparseSlots.clear();
        g_lazyHits.clear();
        g_lazyMnemonic.clear();
        blTargets.clear();
        prologueTargets.clear();

        g_lazyMode = module.size > kDenseMaxModuleSize;
        g_useDense = !g_lazyMode;

        if (g_useDense)
        {
            const size_t slots = static_cast<size_t>((module.size + 3u) / 4u);
            g_denseHits.resize(slots, 0);
            g_denseMnemonic.resize(slots);
            g_denseIsInsn.resize(slots, 0);
        }

        const auto segments = loadExecSegmentsFromFile(module);
        if (segments.empty())
        {
            err = "No executable segments in " + module.name;
            return false;
        }

        if (g_lazyMode)
        {
            return scanHookTargets(module, segments, blTargets, prologueTargets, nullptr, err);
        }

        std::unordered_map<uint64_t, std::string> insnMap;
        if (!scanHookTargets(module, segments, blTargets, prologueTargets, &insnMap, err))
            return false;

        for (const auto &kv : insnMap)
        {
            const size_t slot = static_cast<size_t>(kv.first >> 2);
            if (slot >= g_denseMnemonic.size())
                continue;
            g_denseMnemonic[slot] = kv.second;
            g_denseIsInsn[slot] = 1;
        }
        insnMap.clear();

        err.clear();
        return true;
    }

    static void incrementHit(uint64_t offset)
    {
        if (g_lazyMode)
        {
            g_lazyHits[offset]++;
            g_totalExecutions.fetch_add(1, std::memory_order_relaxed);
            return;
        }

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
        if (runtime >= g_module.base && runtime < g_module.base + g_module.size && inExecRange(runtime))
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
            usleep(g_hookInstalling.load(std::memory_order_relaxed) ? 500 : 100);
        }
    }

    static bool hookRuntimeAddr(uint64_t runtime, bool inBatch)
    {
        if (!inExecRange(runtime) || g_hookedSet.count(runtime))
            return false;

        if (g_interceptor && g_entryListener)
        {
            const bool ok = inBatch
                                ? g_interceptor->attach(reinterpret_cast<void *>(runtime), g_entryListener.get(),
                                                        nullptr)
                                : ([&]() {
                                      g_interceptor->begin_transaction();
                                      const bool attached = g_interceptor->attach(
                                          reinterpret_cast<void *>(runtime), g_entryListener.get(), nullptr);
                                      g_interceptor->end_transaction();
                                      return attached;
                                  })();
            if (ok)
            {
                g_interceptorAddrs.push_back(runtime);
                g_hookedSet.insert(runtime);
                return true;
            }
        }

        dobby_enable_near_branch_trampoline();
        const int rc = DobbyInstrument(reinterpret_cast<void *>(runtime), onEntryInstrument);
        dobby_disable_near_branch_trampoline();
        if (rc == 0)
        {
            g_dobbyAddrs.push_back(runtime);
            g_hookedSet.insert(runtime);
            return true;
        }

        g_hookFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    static std::vector<uint64_t> buildHookPlan(const std::set<uint64_t> &dynsym, const std::set<uint64_t> &blTargets,
                                               const std::set<uint64_t> &prologueTargets, size_t cap)
    {
        std::vector<uint64_t> plan;
        plan.reserve(std::min(cap, dynsym.size() + blTargets.size() + prologueTargets.size()));
        std::unordered_set<uint64_t> seen;

        auto appendUnique = [&](const std::set<uint64_t> &src)
        {
            for (const uint64_t runtime : src)
            {
                if (plan.size() >= cap)
                    return;
                if (!seen.insert(runtime).second)
                    continue;
                plan.push_back(runtime);
            }
        };

        appendUnique(dynsym);
        appendUnique(blTargets);
        if (g_module.size <= kPrologueScanMaxSize)
            appendUnique(prologueTargets);
        return plan;
    }

    static size_t installEntryHooksBatched(const std::vector<uint64_t> &plan,
                                           const std::vector<FileExecSegment> &segments)
    {
        g_interceptorAddrs.clear();
        g_dobbyAddrs.clear();
        g_hookedSet.clear();
        g_hookFailed.store(0, std::memory_order_relaxed);
        g_hookInstallDone.store(0, std::memory_order_relaxed);
        g_hookInstallTotal.store(plan.size(), std::memory_order_relaxed);
        g_hookInstalling.store(true, std::memory_order_release);

        if (plan.empty())
        {
            g_hookInstalling.store(false, std::memory_order_release);
            return 0;
        }

        if (!g_interceptor)
            g_interceptor = Gum::RefPtr<Gum::Interceptor>(Gum::Interceptor_obtain());
        if (!g_entryListener)
            g_entryListener = std::make_unique<NativeEntryListener>();

        size_t installed = 0;
        for (size_t i = 0; i < plan.size(); i += kHookBatchSize)
        {
            if (g_cancelInstall.load(std::memory_order_relaxed))
                break;

            const size_t batchEnd = std::min(plan.size(), i + kHookBatchSize);
            if (g_interceptor)
                g_interceptor->begin_transaction();

            for (size_t j = i; j < batchEnd; ++j)
            {
                if (hookRuntimeAddr(plan[j], true))
                {
                    ++installed;
                    const uint64_t off = plan[j] - g_module.base;
                    if (g_lazyMode && !g_lazyMnemonic.count(off))
                        g_lazyMnemonic[off] = disasmOneRuntime(plan[j], segments);
                }
            }

            if (g_interceptor)
                g_interceptor->end_transaction();

            g_hookInstallDone.store(batchEnd, std::memory_order_relaxed);
            {
                std::lock_guard<std::mutex> lock(g_mutex);
                g_status = "Installing hooks " + std::to_string(batchEnd) + "/" + std::to_string(plan.size()) +
                           " (batched, lib " + std::to_string(g_module.size / (1024 * 1024)) + " MB) ...";
            }
            usleep(8000);
        }

        g_hookInstalling.store(false, std::memory_order_release);
        return installed;
    }

    static void removeEntryHooks()
    {
        g_cancelInstall.store(true, std::memory_order_release);

        if (g_interceptor)
        {
            g_interceptor->begin_transaction();
            for (const uint64_t runtime : g_interceptorAddrs)
                g_interceptor->revert(reinterpret_cast<void *>(runtime));
            g_interceptor->end_transaction();
        }
        for (const uint64_t runtime : g_dobbyAddrs)
            DobbyDestroy(reinterpret_cast<void *>(runtime));

        g_interceptorAddrs.clear();
        g_dobbyAddrs.clear();
        g_hookedSet.clear();
        g_interceptor = nullptr;
        g_entryListener.reset();
        g_hookInstalling.store(false, std::memory_order_release);
        g_hookInstallDone.store(0, std::memory_order_relaxed);
        g_hookInstallTotal.store(0, std::memory_order_relaxed);
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
        std::thread oldSampler;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_active.store(false, std::memory_order_release);
            g_cancelInstall.store(false, std::memory_order_release);
            if (g_samplerThread.joinable())
                oldSampler = std::move(g_samplerThread);
            removeEntryHooks();
            g_cancelInstall.store(false, std::memory_order_release);
            g_starting = true;
            g_module = std::move(module);
            g_hookCap.store(hookCapForModule(g_module.size), std::memory_order_relaxed);
            g_status = "Scanning " + g_module.name + " (" + std::to_string(g_module.size / (1024 * 1024)) +
                       " MB, cap " + std::to_string(g_hookCap.load()) + " hooks) ...";
            g_totalExecutions.store(0, std::memory_order_relaxed);
            g_sampleHits.store(0, std::memory_order_relaxed);
            g_hookHits.store(0, std::memory_order_relaxed);
            g_sampleRounds.store(0, std::memory_order_relaxed);
        }
        if (oldSampler.joinable())
            oldSampler.join();

        std::set<uint64_t> blTargets;
        std::set<uint64_t> prologueTargets;
        std::string err;
        if (!buildMnemonicTables(g_module, blTargets, prologueTargets, err))
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            g_status = err.empty() ? "Failed to build instruction map." : err;
            return;
        }

        std::set<uint64_t> dynsym;
        collectDynsymRuntime(dynsym);

        const auto segments = loadExecSegmentsFromFile(g_module);
        const size_t cap = g_hookCap.load(std::memory_order_relaxed);
        const std::vector<uint64_t> hookPlan = buildHookPlan(dynsym, blTargets, prologueTargets, cap);

        // Start PC sampler immediately so large libs still get hot-spot data while hooks install.
        g_active.store(true, std::memory_order_release);
        g_samplerThread = std::thread(samplerLoop);

        const size_t hookCount = installEntryHooksBatched(hookPlan, segments);

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_starting = false;
            const size_t slots =
                g_lazyMode ? g_lazyMnemonic.size() : (g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size());
            g_status = "Tracing " + g_module.name + " [" + std::to_string(hookCount) + "/" +
                       std::to_string(hookPlan.size()) + " hooks + PC sampler";
            if (g_lazyMode)
                g_status += ", lazy mode";
            g_status += "]. Play the game — hits update live.";
            (void)slots;
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
            g_cancelInstall.store(true, std::memory_order_release);
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
        state.hookInstalling = g_hookInstalling.load(std::memory_order_relaxed);
        state.status = g_status;
        state.moduleName = g_module.name;
        state.base = g_module.base;
        state.threadCount = g_lastThreadCount.load(std::memory_order_relaxed);
        state.insnSlots = g_lazyMode ? g_lazyMnemonic.size()
                                     : (g_useDense ? g_denseMnemonic.size() : g_sparseSlots.size());
        state.totalExecutions = g_totalExecutions.load(std::memory_order_relaxed);
        state.sampleHits = g_sampleHits.load(std::memory_order_relaxed);
        state.hookHits = g_hookHits.load(std::memory_order_relaxed);
        state.sampleRounds = g_sampleRounds.load(std::memory_order_relaxed);
        state.hookedCount = g_interceptorAddrs.size() + g_dobbyAddrs.size();
        state.interceptorCount = g_interceptorAddrs.size();
        state.dobbyCount = g_dobbyAddrs.size();
        state.hookFailed = g_hookFailed.load(std::memory_order_relaxed);
        state.hookInstallDone = g_hookInstallDone.load(std::memory_order_relaxed);
        state.hookInstallTotal = g_hookInstallTotal.load(std::memory_order_relaxed);
        state.hookCap = g_hookCap.load(std::memory_order_relaxed);
        return state;
    }

    std::vector<SoTraceHitEntry> GetSnapshot(bool hideZeroHits, uint64_t minHits, bool sortByHitsDesc)
    {
        std::vector<SoTraceHitEntry> out;
        std::lock_guard<std::mutex> lock(g_mutex);

        if (g_lazyMode)
        {
            out.reserve(g_lazyHits.size());
            const auto segments = loadExecSegmentsFromFile(g_module);
            for (const auto &kv : g_lazyHits)
            {
                if (hideZeroHits && kv.second == 0)
                    continue;
                if (kv.second < minHits)
                    continue;
                SoTraceHitEntry entry;
                entry.offset = kv.first;
                entry.hits = kv.second;
                auto mit = g_lazyMnemonic.find(kv.first);
                if (mit != g_lazyMnemonic.end())
                    entry.mnemonic = mit->second;
                else
                    entry.mnemonic = disasmOneRuntime(g_module.base + kv.first, segments);
                out.push_back(std::move(entry));
            }
        }
        else if (g_useDense)
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
        if (g_lazyMode)
        {
            g_lazyHits.clear();
        }
        else if (g_useDense)
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

        std::fprintf(f, "# Axcel Modified tools - runtime call/instruction trace for %s\n", moduleName.c_str());
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

    bool HookOffset(uint64_t offset, std::string &err)
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        if (!g_active.load(std::memory_order_relaxed))
        {
            err = "Start trace first.";
            return false;
        }
        const uint64_t runtime = g_module.base + offset;
        if (!inExecRange(runtime))
        {
            err = "Offset not in executable segment.";
            return false;
        }
        if (g_hookedSet.count(runtime))
        {
            err = "Already hooked.";
            return true;
        }
        if (!hookRuntimeAddr(runtime, false))
        {
            err = "Hook failed at this offset.";
            return false;
        }
        const auto segments = loadExecSegmentsFromFile(g_module);
        rememberMnemonic(offset, disasmOneRuntime(runtime, segments));
        err.clear();
        return true;
    }
} // namespace SoMonitorTrace
