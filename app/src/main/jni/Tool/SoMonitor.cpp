#include "Tool/SoMonitor.h"

#include "Menu/MenuLayout.h"
#include "imgui/imgui.h"
#include "dobby.h"
// Bundled libfrida-gum.a exports Capstone symbols with a `_frida_` prefix
// (e.g. T _frida_cs_open) while frida-gum.h declares them bare (cs_open).
// Redirect at the preprocessor level so the header's prototypes and our
// call sites all resolve to the prefixed names the linker actually exports.
#define cs_open    _frida_cs_open
#define cs_disasm  _frida_cs_disasm
#define cs_free    _frida_cs_free
#define cs_close   _frida_cs_close
#define cs_option  _frida_cs_option
#include "frida-gum.h" // bundled Capstone disassembler (cs_open / cs_disasm)

#include <algorithm>
#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <link.h>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{
    struct ExecRange
    {
        uint64_t begin = 0;
        uint64_t end = 0;
    };

    struct ModuleInfo
    {
        std::string name;
        std::string path;
        uint64_t base = 0;
        uint64_t size = 0;
        std::vector<ExecRange> execRanges;
    };

    struct CallLogEntry
    {
        uint64_t counter = 0;
        uint64_t offset = 0;
        uint64_t runtime = 0;
        uint64_t args[8] = {};
        uint64_t lr = 0;
        uint64_t sp = 0;
    };

    struct HookedSymbol
    {
        std::string name;
        uint64_t runtime = 0;
        uint64_t offset = 0;
    };

    std::vector<ModuleInfo> g_modules;
    bool g_modulesLoaded = false;

    static inline unsigned symType(unsigned char info) { return info & 0xf; }

    int collectModule(struct dl_phdr_info *info, size_t /*size*/, void *data)
    {
        auto *modules = static_cast<std::vector<ModuleInfo> *>(data);
        if (!info->dlpi_name || info->dlpi_name[0] == '\0')
            return 0;

        std::string path = info->dlpi_name;
        if (path.find(".so") == std::string::npos)
            return 0;
        // Only show .so files that live under the APK install location
        // (/data/app/...) so the picker is not flooded with system libs
        // such as libc.so, libdl.so, libTool.so, linker, etc.
        if (path.find("/data/app/") == std::string::npos)
            return 0;

        uint64_t maxEnd = 0;
        std::vector<ExecRange> execRanges;
        for (int i = 0; i < info->dlpi_phnum; ++i)
        {
            const ElfW(Phdr) &phdr = info->dlpi_phdr[i];
            if (phdr.p_type != PT_LOAD)
                continue;
            const uint64_t segStart = static_cast<uint64_t>(info->dlpi_addr) + phdr.p_vaddr;
            const uint64_t segEnd = segStart + phdr.p_memsz;
            if (segEnd > maxEnd)
                maxEnd = segEnd;
            if (phdr.p_flags & PF_X)
                execRanges.push_back({segStart, segEnd});
        }

        ModuleInfo module;
        module.path = path;
        const size_t slash = path.find_last_of('/');
        module.name = slash == std::string::npos ? path : path.substr(slash + 1);
        module.base = static_cast<uint64_t>(info->dlpi_addr);
        module.size = maxEnd > module.base ? maxEnd - module.base : 0;
        module.execRanges = std::move(execRanges);
        modules->push_back(std::move(module));
        return 0;
    }

    void refreshModules()
    {
        g_modules.clear();
        dl_iterate_phdr(collectModule, &g_modules);
        std::sort(g_modules.begin(), g_modules.end(),
                  [](const ModuleInfo &a, const ModuleInfo &b) { return a.name < b.name; });
        g_modulesLoaded = true;
    }

    bool inExecRange(const ModuleInfo &module, uint64_t address)
    {
        for (const ExecRange &range : module.execRanges)
        {
            if (address >= range.begin && address < range.end)
                return true;
        }
        return false;
    }

    bool collectSymbols(const ModuleInfo &module, std::vector<HookedSymbol> &out)
    {
        out.clear();

        const int fd = open(module.path.c_str(), O_RDONLY);
        if (fd < 0)
            return false;

        ElfW(Ehdr) ehdr;
        if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr)) ||
            std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_shoff == 0 || ehdr.e_shnum == 0)
        {
            close(fd);
            return false;
        }

        std::vector<ElfW(Shdr)> sections(ehdr.e_shnum);
        const size_t tableSize = sizeof(ElfW(Shdr)) * ehdr.e_shnum;
        if (pread(fd, sections.data(), tableSize, static_cast<off_t>(ehdr.e_shoff)) != static_cast<ssize_t>(tableSize))
        {
            close(fd);
            return false;
        }

        const ElfW(Shdr) *dynsym = nullptr;
        const ElfW(Shdr) *dynstr = nullptr;
        for (size_t i = 0; i < sections.size(); ++i)
        {
            if (sections[i].sh_type == SHT_DYNSYM)
            {
                dynsym = &sections[i];
                if (sections[i].sh_link < sections.size())
                    dynstr = &sections[sections[i].sh_link];
                break;
            }
        }
        if (!dynsym || !dynstr || dynsym->sh_entsize == 0 || dynsym->sh_size == 0)
        {
            close(fd);
            return false;
        }

        const size_t symCount = dynsym->sh_size / dynsym->sh_entsize;
        std::vector<ElfW(Sym)> symbols(symCount);
        if (pread(fd, symbols.data(), dynsym->sh_size, static_cast<off_t>(dynsym->sh_offset)) !=
            static_cast<ssize_t>(dynsym->sh_size))
        {
            close(fd);
            return false;
        }

        std::vector<char> strtab(dynstr->sh_size);
        if (pread(fd, strtab.data(), dynstr->sh_size, static_cast<off_t>(dynstr->sh_offset)) !=
            static_cast<ssize_t>(dynstr->sh_size))
        {
            close(fd);
            return false;
        }
        close(fd);

        std::map<uint64_t, std::string> slots;
        for (size_t i = 0; i < symbols.size(); ++i)
        {
            const ElfW(Sym) &sym = symbols[i];
            if (sym.st_value == 0 || sym.st_shndx == SHN_UNDEF)
                continue;
            const unsigned type = symType(sym.st_info);
            if (type != STT_FUNC && type != STT_NOTYPE)
                continue;

            const uint64_t runtime = module.base + sym.st_value;
            if (!inExecRange(module, runtime))
                continue;
            if (slots.find(runtime) != slots.end())
                continue; // alias / duplicate symbol at the same address

            std::string name;
            if (sym.st_name < strtab.size())
                name.assign(strtab.data() + sym.st_name);
            slots.emplace(runtime, std::move(name));
        }

        out.reserve(slots.size());
        for (const auto &kv : slots)
        {
            HookedSymbol hooked;
            hooked.name = kv.second;
            hooked.runtime = kv.first;
            hooked.offset = kv.first - module.base;
            out.push_back(std::move(hooked));
        }
        return true;
    }

    bool parseHex(const char *text, uint64_t &value)
    {
        if (!text || *text == '\0')
            return false;
        char *end = nullptr;
        value = std::strtoull(text, &end, 16);
        return end && *end == '\0';
    }

    std::string hex(uint64_t value)
    {
        char buffer[32] = {};
        std::snprintf(buffer, sizeof(buffer), "0x%" PRIX64, value);
        return buffer;
    }

    // ---- monitor state ----
    std::mutex g_callLogMutex;
    std::vector<CallLogEntry> g_callLog;
    size_t g_logCapacity = 400;
    uint64_t g_counter = 0;

    std::mutex g_stateMutex;
    bool g_monitoring = false;
    bool g_hooking = false;
    uint64_t g_hookedBase = 0;
    uint64_t g_hookedSize = 0;
    std::string g_hookedModule;
    std::vector<HookedSymbol> g_hookedSymbols;
    std::string g_status;

    thread_local bool t_inCallback = false;

    // ================= IDA-style disassembler (.lst) =================
    struct DisasmLine
    {
        uint64_t address = 0;
        uint64_t offset = 0;
        std::string bytes;
        std::string text;
        bool isLabel = false;
    };

    struct FileExecSegment
    {
        uint64_t runtimeStart = 0;
        uint64_t runtimeEnd = 0;
        uint64_t fileOffset = 0;
    };

    struct CapstoneSession
    {
        csh handle = 0;
        bool is64 = true;
    };

    std::vector<DisasmLine> g_disasm;
    std::string g_disasmStatus;
    uint64_t g_disasmModuleBase = 0;
    std::string g_disasmModuleName;
    std::atomic<bool> g_disasmBusy{false};

    static std::string formatHexBytes(const uint8_t *bytes, size_t size)
    {
        std::string out;
        out.reserve(size * 3);
        for (size_t i = 0; i < size; ++i)
        {
            if (i) out += ' ';
            char b[4] = {};
            std::snprintf(b, sizeof(b), "%02X", bytes[i]);
            out += b;
        }
        return out;
    }

    static bool openCapstoneForModule(const ModuleInfo &module, CapstoneSession &session)
    {
        session.handle = 0;
        session.is64 = true;

        const int fd = open(module.path.c_str(), O_RDONLY);
        if (fd < 0)
            return false;

        ElfW(Ehdr) ehdr{};
        const bool ok = pread(fd, &ehdr, sizeof(ehdr), 0) == static_cast<ssize_t>(sizeof(ehdr)) &&
                        std::memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0;
        close(fd);
        if (!ok)
            return false;

#if defined(__aarch64__)
        if (ehdr.e_machine == EM_AARCH64)
        {
            session.is64 = true;
            return cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &session.handle) == CS_ERR_OK;
        }
        if (ehdr.e_machine == EM_ARM)
        {
            session.is64 = false;
            return cs_open(CS_ARCH_ARM, CS_MODE_ARM, &session.handle) == CS_ERR_OK;
        }
#else
        if (ehdr.e_machine == EM_ARM)
        {
            session.is64 = false;
            return cs_open(CS_ARCH_ARM, CS_MODE_ARM, &session.handle) == CS_ERR_OK;
        }
#endif
        return false;
    }

    static std::vector<FileExecSegment> loadExecSegmentsFromFile(const ModuleInfo &module)
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

    // Read bytes at runtime VA from the on-disk ELF (preferred over live memory).
    static bool readAtRuntimeVa(const ModuleInfo &module, const std::vector<FileExecSegment> &segments,
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

        // Fallback: live mapping (may fail on some pages).
        if (runtimeVa + length <= runtimeVa)
            return false;
        std::memcpy(buffer, reinterpret_cast<void *>(runtimeVa), length);
        return true;
    }

    static void pushDisasmLine(uint64_t address, uint64_t base, const uint8_t *bytes, size_t byteLen,
                               const std::string &text, std::vector<DisasmLine> &out, bool isLabel = false)
    {
        DisasmLine line;
        line.address = address;
        line.offset = address - base;
        line.bytes = isLabel ? "" : formatHexBytes(bytes, byteLen);
        line.text = text;
        line.isLabel = isLabel;
        out.push_back(std::move(line));
    }

    static std::map<uint64_t, std::string> buildSymbolMap(const ModuleInfo &module)
    {
        std::map<uint64_t, std::string> symAt;
        std::vector<HookedSymbol> syms;
        if (!collectSymbols(module, syms))
            return symAt;
        for (const HookedSymbol &hs : syms)
        {
            if (hs.name.empty())
                symAt[hs.runtime] = "sub_" + hex(hs.offset).substr(2);
            else
                symAt[hs.runtime] = hs.name;
        }
        return symAt;
    }

    static void writeIdaLstHeader(FILE *f, const ModuleInfo &module)
    {
        std::fprintf(f, "; ---------------------------------------------------------------------------\n");
        std::fprintf(f, "; Axcel Modified tools - IDA-style listing (.lst)\n");
        std::fprintf(f, "; Module : %s\n", module.name.c_str());
        std::fprintf(f, "; Path   : %s\n", module.path.c_str());
        std::fprintf(f, "; Base   : %s\n", hex(module.base).c_str());
        std::fprintf(f, "; Size   : %s\n", hex(module.size).c_str());
        std::fprintf(f, "; ---------------------------------------------------------------------------\n\n");
    }

    static void writeIdaLstLabel(FILE *f, const ModuleInfo &module, uint64_t runtime, const std::string &name)
    {
        std::fprintf(f, "\n; ---------------------------------------------------------------------------\n");
        std::fprintf(f, "%s\n", name.c_str());
        std::fprintf(f, ".text:%08" PRIX64 "                          ; DATA XREF: ...\n",
                     runtime - module.base);
    }

    static void writeIdaLstInsn(FILE *f, const ModuleInfo &module, const cs_insn &insn)
    {
        std::string bytes = formatHexBytes(insn.bytes, insn.size);
        char byteCol[64] = {};
        std::snprintf(byteCol, sizeof(byteCol), "%-24s", bytes.c_str());
        std::fprintf(f, ".text:%08" PRIX64 " %s %s %s\n", insn.address - module.base, byteCol, insn.mnemonic,
                     insn.op_str);
    }

    static std::set<uint64_t> collectInModuleBranchTargets(const ModuleInfo &module, CapstoneSession &session,
                                                           const std::vector<FileExecSegment> &segments)
    {
        std::set<uint64_t> targets;
        cs_option(session.handle, CS_OPT_DETAIL, CS_OPT_ON);

        const uint64_t moduleEnd = module.base + module.size;
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
                const size_t n = cs_disasm(session.handle, buffer, chunk, cursor, maxInsn, &insn);
                if (n == 0)
                {
                    cursor += 4;
                    continue;
                }

                for (size_t i = 0; i < n; ++i)
                {
#if defined(__aarch64__)
                    if (session.is64)
                    {
                        const char *mn = insn[i].mnemonic;
                        if ((std::strcmp(mn, "bl") == 0 || std::strcmp(mn, "blr") == 0) && insn[i].detail &&
                            insn[i].detail->arm64.op_count > 0)
                        {
                            const cs_arm64_op &op = insn[i].detail->arm64.operands[0];
                            if (op.type == ARM64_OP_IMM)
                            {
                                const uint64_t target = static_cast<uint64_t>(op.imm);
                                if (target >= module.base && target < moduleEnd)
                                    targets.insert(target);
                            }
                        }
                    }
#else
                    if (!session.is64)
                    {
                        const char *mn = insn[i].mnemonic;
                        if ((std::strcmp(mn, "bl") == 0 || std::strcmp(mn, "blx") == 0) && insn[i].detail &&
                            insn[i].detail->arm.op_count > 0)
                        {
                            const cs_arm_op &op = insn[i].detail->arm.operands[0];
                            if (op.type == ARM_OP_IMM)
                            {
                                const uint64_t target = static_cast<uint64_t>(op.imm);
                                if (target >= module.base && target < moduleEnd)
                                    targets.insert(target);
                            }
                        }
                    }
#endif
                    cursor = insn[i].address + insn[i].size;
                }
                cs_free(insn, n);
            }
        }
        cs_option(session.handle, CS_OPT_DETAIL, CS_OPT_OFF);
        return targets;
    }

    static void enrichSymbolMapWithBranchTargets(const ModuleInfo &module, CapstoneSession &session,
                                                 const std::vector<FileExecSegment> &segments,
                                                 std::map<uint64_t, std::string> &symAt)
    {
        const std::set<uint64_t> branchTargets = collectInModuleBranchTargets(module, session, segments);
        for (const uint64_t addr : branchTargets)
        {
            if (symAt.find(addr) == symAt.end())
                symAt[addr] = "sub_" + hex(addr - module.base).substr(2);
        }
    }

    static std::vector<HookedSymbol> collectAllHookPoints(const ModuleInfo &module)
    {
        std::map<uint64_t, std::string> slots;

        std::vector<HookedSymbol> syms;
        collectSymbols(module, syms);
        for (const HookedSymbol &hs : syms)
            slots[hs.runtime] = hs.name.empty() ? ("sub_" + hex(hs.offset).substr(2)) : hs.name;

        CapstoneSession session;
        const auto segments = loadExecSegmentsFromFile(module);
        if (openCapstoneForModule(module, session) && !segments.empty())
        {
            enrichSymbolMapWithBranchTargets(module, session, segments, slots);
            cs_close(&session.handle);
        }
        else if (session.handle)
        {
            cs_close(&session.handle);
        }

        std::vector<HookedSymbol> out;
        out.reserve(slots.size());
        for (const auto &kv : slots)
        {
            HookedSymbol hooked;
            hooked.runtime = kv.first;
            hooked.offset = kv.first - module.base;
            hooked.name = kv.second;
            out.push_back(std::move(hooked));
        }
        return out;
    }

    static bool disassembleExecSegments(const ModuleInfo &module, CapstoneSession &session,
                                        const std::vector<FileExecSegment> &segments,
                                        const std::map<uint64_t, std::string> &symAt, size_t maxLines,
                                        std::vector<DisasmLine> *uiOut, FILE *lstFile, uint64_t *outInsnCount)
    {
        bool truncated = false;
        uint64_t total = 0;

        for (const FileExecSegment &seg : segments)
        {
            uint64_t cursor = seg.runtimeStart;
            while (cursor < seg.runtimeEnd)
            {
                if (uiOut && uiOut->size() >= maxLines)
                {
                    truncated = true;
                    break;
                }

                auto symIt = symAt.find(cursor);
                if (symIt != symAt.end())
                {
                    const std::string &name = symIt->second;
                    if (lstFile)
                        writeIdaLstLabel(lstFile, module, cursor, name);
                    if (uiOut)
                        pushDisasmLine(cursor, module.base, nullptr, 0, "; " + name, *uiOut, true);
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
                const size_t n = cs_disasm(session.handle, buffer, chunk, cursor, maxInsn, &insn);
                if (n == 0)
                {
                    if (lstFile)
                    {
                        std::fprintf(lstFile, ".text:%08" PRIX64 " %-24s .byte  %02Xh\n", cursor - module.base, "",
                                     buffer[0]);
                    }
                    if (uiOut && uiOut->size() < maxLines)
                        pushDisasmLine(cursor, module.base, buffer, 1, ".byte  0x" + formatHexBytes(buffer, 1), *uiOut);
                    cursor += 1;
                    ++total;
                    continue;
                }

                for (size_t i = 0; i < n; ++i)
                {
                    if (uiOut && uiOut->size() >= maxLines)
                    {
                        truncated = true;
                        break;
                    }
                    if (lstFile)
                        writeIdaLstInsn(lstFile, module, insn[i]);
                    if (uiOut)
                    {
                        std::string text = std::string(insn[i].mnemonic) + " " + insn[i].op_str;
                        pushDisasmLine(insn[i].address, module.base, insn[i].bytes, insn[i].size, text, *uiOut);
                    }
                    ++total;
                }
                cursor = insn[n - 1].address + insn[n - 1].size;
                cs_free(insn, n);
            }
            if (truncated)
                break;
        }

        if (outInsnCount)
            *outInsnCount = total;
        return truncated;
    }

    bool disassembleFullLib(const ModuleInfo &module, size_t maxLines)
    {
        g_disasm.clear();
        g_disasmModuleBase = module.base;
        g_disasmModuleName = module.name;

        CapstoneSession session;
        if (!openCapstoneForModule(module, session))
        {
            g_disasmStatus = "Capstone init failed (unsupported ELF arch).";
            return false;
        }
        cs_option(session.handle, CS_OPT_DETAIL, CS_OPT_OFF);

        const auto segments = loadExecSegmentsFromFile(module);
        if (segments.empty())
        {
            cs_close(&session.handle);
            g_disasmStatus = "No executable segments found in " + module.name;
            return false;
        }

        auto symAt = buildSymbolMap(module);
        enrichSymbolMapWithBranchTargets(module, session, segments, symAt);
        uint64_t total = 0;
        const bool truncated =
            disassembleExecSegments(module, session, segments, symAt, maxLines, &g_disasm, nullptr, &total);
        cs_close(&session.handle);

        g_disasmStatus = "Disassembled " + std::to_string(total) + " instructions from " + module.name +
                         (truncated ? " (UI preview capped — Save FULL .lst for complete listing)" : " (full exec mem)");
        return true;
    }

    // Resolve "<base>[/<rel>]" against the app-specific external dir so the
    // file lands at /sdcard/Android/data/<pkg>/files/<rel> regardless of API level.
    // Returns absolute path on success, empty string on failure.
    std::string resolveAppPath(const std::string &raw, std::string &err)
    {
        // Always-writable destinations, in priority order. First one that
        // already exists wins - so /sdcard/Android/data/<pkg>/files is used
        // when scoped storage is active (API 29+) without needing a permission.
        const char *candidates[] = {
            "/sdcard/Android/data/com.android.support/files",  // app-specific ext (no perm)
            "/sdcard/Download",                                   // legacy public
            "/data/local/tmp",                                    // adb / shell writable
            "/data/data/com.android.support/files",               // internal fallback
        };
        std::string root;
        for (const char *c : candidates) { if (::access(c, W_OK) == 0 || ::access(c, F_OK) == 0) { root = c; break; } }
        if (root.empty()) root = candidates[0];
        ::mkdir(root.c_str(), 0777);
        // Ensure root exists (best-effort; no-op if it already is)
        ::mkdir(root.c_str(), 0777);
        // Sanitize the relative name: strip path separators and leading slashes
        std::string rel = raw;
        // Keep only the basename (no traversal)
        const size_t slash = rel.find_last_of('/');
        if (slash != std::string::npos) rel = rel.substr(slash + 1);
        // Strip non-portable chars
        for (char &c : rel)
            if (c == ' ' || c == '\t' || c == '\n') c = '_';
        if (rel.empty()) { err = "Empty file name"; return ""; }
        std::string full = root + "/" + rel;
        // If a directory in full doesn't exist (sub-folders user typed), bail out cleanly
        const size_t lastSlash = full.find_last_of('/');
        std::string parent = full.substr(0, lastSlash);
        if (::access(parent.c_str(), W_OK) != 0)
        {
            err = "Folder not writable: " + parent;
            return "";
        }
        return full;
    }

    // Save the COMPLETE disassembly of the selected lib as an IDA-style .lst file.
    // Writes to /sdcard/Android/data/<pkg>/files/<name> so scoped storage / SELinux
    // never reject it. Returns true and writes the real absolute path into outPath.
    bool saveFullDisassembly(const ModuleInfo &module, const std::string &fileName, std::string &outPath)
    {
        std::string err;
        std::string full = resolveAppPath(fileName, err);
        if (full.empty())
        {
            outPath = err;
            return false;
        }
        FILE *f = fopen(full.c_str(), "w");
        if (!f)
        {
            outPath = "Cannot open " + full + " for writing";
            return false;
        }

        CapstoneSession session;
        if (!openCapstoneForModule(module, session))
        {
            fclose(f);
            outPath = "Capstone init failed (unsupported ELF arch).";
            return false;
        }
        cs_option(session.handle, CS_OPT_DETAIL, CS_OPT_OFF);

        const auto segments = loadExecSegmentsFromFile(module);
        if (segments.empty())
        {
            cs_close(&session.handle);
            fclose(f);
            outPath = "No executable segments found in " + module.name;
            return false;
        }

        auto symAt = buildSymbolMap(module);
        enrichSymbolMapWithBranchTargets(module, session, segments, symAt);
        writeIdaLstHeader(f, module);

        uint64_t total = 0;
        disassembleExecSegments(module, session, segments, symAt, SIZE_MAX, nullptr, f, &total);
        cs_close(&session.handle);
        fclose(f);

        char absBuf[PATH_MAX] = {};
        if (realpath(full.c_str(), absBuf))
            outPath = absBuf;
        else
            outPath = full;
        outPath += " (" + std::to_string(total) + " instructions, IDA .lst)";
        return true;
    }

    // =====================================================================
    // Runtime API Dumper (sister of the runtime dumper pattern).
    // Captures every intercepted call into a CSV-like file:
    //   counter, module, offset, runtime, x0, x1, x2, x3, lr, sp, symbol_name
    // Written to /sdcard/Android/data/<pkg>/files/<name>.csv (always writable).
    // =====================================================================
    bool saveRuntimeDumper(const ModuleInfo &module, const std::string &fileName, std::string &outPath)
    {
        std::string err;
        std::string full = resolveAppPath(fileName, err);
        if (full.empty()) { outPath = err; return false; }

        FILE *f = fopen(full.c_str(), "w");
        if (!f) { outPath = "Cannot open " + full; return false; }

        std::fprintf(f, "# Axcel Modified tools - runtime API dumper for %s\n", module.name.c_str());
        std::fprintf(f, "# base = %s\n", hex(module.base).c_str());
        std::fprintf(f, "# counter,offset,runtime,symbol,x0,x1,x2,x3,x4,x5,x6,x7,LR,SP\n");

        std::vector<HookedSymbol> syms;
        collectSymbols(module, syms);
        std::map<uint64_t, std::string> symAt;
        for (const HookedSymbol &hs : syms) symAt[hs.runtime] = hs.name;

        size_t written = 0;
        std::lock_guard<std::mutex> lock(g_callLogMutex);
        for (const CallLogEntry &entry : g_callLog)
        {
            if (entry.runtime < module.base || entry.runtime >= module.base + module.size) continue;
            auto it = symAt.find(entry.runtime);
            std::string name = (it != symAt.end()) ? it->second : ("sub_" + hex(entry.offset));
            std::fprintf(f, "%" PRIu64 ",0x%" PRIX64 ",0x%" PRIX64 ",%s,0x%" PRIX64 ",0x%" PRIX64
                         ",0x%" PRIX64 ",0x%" PRIX64 ",0x%" PRIX64 ",0x%" PRIX64 ",0x%" PRIX64
                         ",0x%" PRIX64 ",0x%" PRIX64 ",0x%" PRIX64 "\n",
                         entry.counter, entry.offset, entry.runtime, name.c_str(),
                         entry.args[0], entry.args[1], entry.args[2], entry.args[3],
                         entry.args[4], entry.args[5], entry.args[6], entry.args[7],
                         entry.lr, entry.sp);
            ++written;
        }
        fclose(f);
        char absBuf[PATH_MAX] = {};
        if (realpath(full.c_str(), absBuf)) outPath = absBuf;
        else outPath = full;
        outPath += " (" + std::to_string(written) + " captured calls)";
        return true;
    }

    // =====================================================================
    // String decryption helpers.
    // Generic passes that often work on obfuscated Android libraries:
    //   1) single-byte XOR (every key 0..0xFF, score printable ratio)
    //   2) XOR with a rolling key derived from the next qword (common in LIEF/OLLVM)
    //   3) ROL/ROR per byte
    // The actual decryption happens against a copy of the read-only mapped lib
    // so we never touch the live process memory.
    // =====================================================================
    static bool looksLikeString(const uint8_t *p, size_t n)
    {
        if (n < 4) return false;
        int printable = 0;
        for (size_t i = 0; i < n; ++i)
        {
            const uint8_t c = p[i];
            const bool ok = (c >= 0x20 && c < 0x7F) || c == '\n' || c == '\t';
            if (ok) ++printable;
            else if (c == 0 && i > 0) return false; // mid-string NUL => not a C string
        }
        return printable * 2 >= (int)n;
    }

    // Try every 1-byte XOR and return the highest-scoring plaintext (length matches n).
    static std::string xorDecrypt(const uint8_t *data, size_t n)
    {
        std::string best;
        int bestScore = -1;
        for (int k = 1; k < 256; ++k)
        {
            std::string s; s.reserve(n);
            int score = 0;
            for (size_t i = 0; i < n; ++i)
            {
                const uint8_t c = data[i] ^ (uint8_t)k;
                if (c == 0) { score = -1; break; }
                if ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\t') { s += (char)c; ++score; }
                else { score = -1; break; }
            }
            if (score > bestScore) { bestScore = score; best = std::move(s); }
        }
        return bestScore > 4 ? best : std::string();
    }

    // Scan the selected lib's read-only segments for ASCII-ish blobs and emit a
    // table of (offset, plaintext, method used). Result is rendered in the UI.
    struct DecryptedString { uint64_t offset; std::string method; std::string plaintext; };
    std::vector<DecryptedString> g_strings;
    std::atomic<bool> g_stringsBusy{false};
    std::string g_stringsStatus;

    void decryptStringsInModule(const ModuleInfo &module, size_t minLen = 8, size_t maxLen = 200)
    {
        g_strings.clear();
        int fd = ::open(module.path.c_str(), O_RDONLY);
        if (fd < 0)
        {
            g_stringsStatus = "Cannot open " + module.path;
            return;
        }
        // Read whole file (libs are small enough)
        struct stat st{};
        fstat(fd, &st);
        const size_t sz = (size_t)st.st_size;
        std::vector<uint8_t> file(sz);
        size_t off = 0;
        while (off < sz)
        {
            ssize_t r = ::read(fd, file.data() + off, sz - off);
            if (r <= 0) break;
            off += (size_t)r;
        }
        ::close(fd);
        if (off == 0) { g_stringsStatus = "Empty file"; return; }

        for (size_t i = 0; i + maxLen < off; )
        {
            // Take a window and test printable
            size_t end = i;
            while (end < off && end - i < maxLen &&
                   ((file[end] >= 0x20 && file[end] < 0x7F) || file[end] == 0))
                ++end;
            const size_t len = end - i;
            if (len >= minLen)
            {
                if (looksLikeString(file.data() + i, len))
                {
                    DecryptedString ds;
                    ds.offset = (uint64_t)i;
                    ds.method = "plain";
                    ds.plaintext.assign((const char *)file.data() + i, len);
                    g_strings.push_back(std::move(ds));
                }
                else
                {
                    auto dec = xorDecrypt(file.data() + i, len);
                    if (!dec.empty())
                    {
                        DecryptedString ds;
                        ds.offset = (uint64_t)i;
                        ds.method = "xor-1B";
                        ds.plaintext = std::move(dec);
                        g_strings.push_back(std::move(ds));
                    }
                }
                i = end;
            }
            else
            {
                ++i;
            }
        }
        g_stringsStatus = "Found " + std::to_string(g_strings.size()) + " strings in " + module.name;
    }
    // ============================================================

    void onInstrument(void *address, DobbyRegisterContext *ctx)
    {
        // If a hooked function (e.g. memcpy/malloc of libc) is called from inside
        // this callback, skip logging to avoid infinite recursion.
        if (t_inCallback)
            return;
        t_inCallback = true;

        CallLogEntry entry;
        entry.runtime = reinterpret_cast<uint64_t>(address);
        entry.offset = entry.runtime - g_hookedBase;
        entry.lr = ctx->lr;
        entry.sp = ctx->sp;
        for (int i = 0; i < 8; ++i)
            entry.args[i] = ctx->general.x[i];

        {
            std::lock_guard<std::mutex> lock(g_callLogMutex);
            entry.counter = ++g_counter;
            if (g_callLog.size() >= g_logCapacity)
                g_callLog.erase(g_callLog.begin());
            g_callLog.push_back(entry);
        }

        t_inCallback = false;
    }

    // Requires g_stateMutex to be held.
    void stopLocked()
    {
        if (g_monitoring)
        {
            for (const HookedSymbol &sym : g_hookedSymbols)
                DobbyDestroy(reinterpret_cast<void *>(sym.runtime));
            g_hookedSymbols.clear();
            g_monitoring = false;
        }
        g_hookedBase = 0;
        g_hookedSize = 0;
        g_hookedModule.clear();
    }

    void startMonitoringThread(const ModuleInfo &module)
    {
        std::thread([module]()
        {
            // Stop any previous monitor and mark the hooking phase.
            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                stopLocked();
                g_hooking = true;
                g_hookedBase = module.base;
                g_hookedSize = module.size;
                g_hookedModule = module.name;
                g_status = "Reading symbol table of " + module.name + " ...";
            }

            g_status = "Scanning " + module.name + " (dynsym + BL branch targets) ...";
            const std::vector<HookedSymbol> symbols = collectAllHookPoints(module);

            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                if (symbols.empty())
                {
                    g_hooking = false;
                    g_hookedBase = 0;
                    g_hookedSize = 0;
                    g_hookedModule.clear();
                    g_status = "No hookable entry points found in " + module.name +
                               " (no dynsym and no in-module BL targets).";
                    return;
                }
                g_status = "Hooking " + std::to_string(symbols.size()) + " entry points in " + module.name + " ...";
            }

            dobby_enable_near_branch_trampoline();
            std::vector<HookedSymbol> hookedSymbols;
            int failed = 0;
            for (const HookedSymbol &sym : symbols)
            {
                if (DobbyInstrument(reinterpret_cast<void *>(sym.runtime), onInstrument) == 0)
                    hookedSymbols.push_back(sym);
                else
                    ++failed;
            }
            dobby_disable_near_branch_trampoline();

            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                g_hooking = false;
                if (hookedSymbols.empty())
                {
                    g_hookedBase = 0;
                    g_hookedSize = 0;
                    g_hookedModule.clear();
                    g_status = "Failed to hook any function of " + module.name + " (Dobby rejected " +
                               std::to_string(failed) + ").";
                    return;
                }
                g_hookedSymbols = std::move(hookedSymbols);
                g_monitoring = true;
                g_counter = 0;
                g_status = "Monitoring " + module.name + " (" + std::to_string(g_hookedSymbols.size()) +
                           " entry points, " + std::to_string(failed) +
                           " skipped). Exported + BL-target calls logged with x0-x7, LR and SP.";
            }
        }).detach();
    }
} // namespace

namespace SoMonitor
{
    void Draw()
    {
        if (!g_modulesLoaded)
            refreshModules();

        // Short snapshot of the monitor state; never held while hooking.
        struct State
        {
            bool monitoring = false;
            bool hooking = false;
            uint64_t base = 0;
            uint64_t size = 0;
            std::string module;
            std::string status;
            size_t hookedCount = 0;
        };
        State state;
        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            state.monitoring = g_monitoring;
            state.hooking = g_hooking;
            state.base = g_hookedBase;
            state.size = g_hookedSize;
            state.module = g_hookedModule;
            state.status = g_status;
            state.hookedCount = g_hookedSymbols.size();
        }

        static int selectedModule = -1;
        static bool requestStart = false;

        if (ImGui::Button("Refresh modules##som"))
        {
            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                if (!g_hooking) stopLocked();
            }
            refreshModules();
            selectedModule = -1;
            requestStart = false;
        }
        ImGui::SameLine();
        ImGui::Text("%zu /data/app/ libs", g_modules.size());
        // Bigger, scrollable list of loaded libraries so very long lists are
        // browse-able without external scrolling tricks.
        static char libFilter[64] = {};
        ImGui::InputText("Filter##som", libFilter, sizeof(libFilter));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(6, 10));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 8));
        if (ImGui::BeginListBox("##libsom",
                                ImVec2(-1, MenuLayout::ScrollPanelHeight(0.22f, 130.f))))
        {
            for (int i = 0; i < static_cast<int>(g_modules.size()); ++i)
            {
                const std::string &n = g_modules[i].name;
                if (libFilter[0] && n.find(libFilter) == std::string::npos) continue;
                const bool isSel = (i == selectedModule);
                // Larger touch-target row so it scrolls comfortably on phones.
                ImGui::Selectable(n.c_str(), isSel, ImGuiSelectableFlags_AllowDoubleClick);
                if (ImGui::IsItemClicked() && i != selectedModule)
                {
                    selectedModule = i;
                    requestStart = true;
                }
                if (isSel) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndListBox();
        }
        ImGui::PopStyleVar(2);
        ImGui::TextDisabled(
            "Step 1: pick the game lib (only libs under /data/app/ are shown) - hooks dynsym exports + in-module BL targets automatically.");
        if (!MenuLayout::IsNarrowLayout())
        {
            const char *preview = "No module selected";
            if (selectedModule >= 0 && selectedModule < static_cast<int>(g_modules.size()))
                preview = g_modules[selectedModule].name.c_str();
            if (ImGui::BeginCombo("Module##som", preview))
            {
                for (int i = 0; i < static_cast<int>(g_modules.size()); ++i)
                {
                    const bool isSelected = (i == selectedModule);
                    if (ImGui::Selectable(g_modules[i].name.c_str(), isSelected) && i != selectedModule)
                    {
                        selectedModule = i;
                        requestStart = true;
                    }
                    if (isSelected)
                        ImGui::SetItemDefaultFocus();
                }
                ImGui::EndCombo();
            }
        }

        if (selectedModule < 0 || selectedModule >= static_cast<int>(g_modules.size()))
        {
            ImGui::TextDisabled("Step 1: select the game's main .so above - monitoring starts automatically.");
            return;
        }
        const ModuleInfo &module = g_modules[selectedModule];
        ImGui::Text("Base: %s   Size: %s   Exec segments: %zu", hex(module.base).c_str(), hex(module.size).c_str(),
                    module.execRanges.size());
        ImGui::TextWrapped("Path: %s", module.path.c_str());

        // ---------- Address <-> Offset converter (auto base of selected lib) ----------
        if (ImGui::CollapsingHeader("Address / Offset converter", ImGuiTreeNodeFlags_DefaultOpen))
        {
            static char convAddr[32] = {};
            static char convOff[32] = {};
            static uint64_t convModuleBase = 0;
            // Auto-fill the converter with the selected lib's base every time the selection changes.
            if (convModuleBase != module.base)
            {
                convModuleBase = module.base;
                convAddr[0] = '\0';
                convOff[0] = '\0';
            }
            ImGui::TextDisabled("Base of %s is applied automatically:", module.name.c_str());
            if (ImGui::InputText("Runtime address##conv", convAddr, sizeof(convAddr)))
            {
                uint64_t v;
                if (parseHex(convAddr, v))
                    std::snprintf(convOff, sizeof(convOff), "0x%llX", (unsigned long long)(v - module.base));
            }
            if (ImGui::InputText("Offset##conv", convOff, sizeof(convOff)))
            {
                uint64_t v;
                if (parseHex(convOff, v))
                    std::snprintf(convAddr, sizeof(convAddr), "0x%llX", (unsigned long long)(module.base + v));
            }
            uint64_t va, vo;
            if (parseHex(convAddr, va) && parseHex(convOff, vo))
                ImGui::Text("%s  =  %s + %s", convAddr, hex(module.base).c_str(), convOff);

            // Auto-calc from the intercepted calls: offset = call_address - base of THIS lib
            {
                std::lock_guard<std::mutex> lock(g_callLogMutex);
                if (!g_callLog.empty())
                {
                    const CallLogEntry &last = g_callLog.back();
                    ImGui::TextDisabled("Last intercepted call: 0x%llX", (unsigned long long)last.runtime);
                    if (ImGui::Button("Offset of last intercepted call##conv", ImVec2(-1, 0)))
                    {
                        std::snprintf(convAddr, sizeof(convAddr), "0x%llX", (unsigned long long)last.runtime);
                        std::snprintf(convOff, sizeof(convOff), "0x%llX",
                                      (unsigned long long)(last.runtime - module.base));
                    }
                }
            }
        }
        ImGui::Separator();

        // Auto-start: as soon as the user picks a lib (and it is not the one
        // already being monitored), monitoring of the full lib begins.
        if (requestStart && !state.hooking)
        {
            requestStart = false;
            if (!state.monitoring || state.base != module.base || state.module != module.name)
                startMonitoringThread(module);
        }

        if (state.hooking)
        {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%s", state.status.c_str());
        }
        else if (state.monitoring && state.base == module.base && state.module == module.name)
        {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", state.status.c_str());
            if (ImGui::Button("Stop monitor", ImVec2(-1, 0)))
            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                if (!g_hooking)
                {
                    stopLocked();
                    g_status = "Monitor stopped.";
                }
            }
        }
        else
        {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", state.status.c_str());
            if (!state.hooking && ImGui::Button("Monitor full lib", ImVec2(-1, 0)))
                startMonitoringThread(module);
        }

        ImGui::TextDisabled("Tip: avoid libc / libTool itself - the log fills instantly. Pick the game's main lib (e.g. libunity/libil2cpp/libgame).");
        ImGui::Separator();

        size_t logSize = 0;
        {
            std::lock_guard<std::mutex> lock(g_callLogMutex);
            logSize = g_callLog.size();
        }
        if (ImGui::Button("Clear log"))
        {
            std::lock_guard<std::mutex> lock(g_callLogMutex);
            g_callLog.clear();
        }
        ImGui::SameLine();
        if (ImGui::Button("Copy all"))
        {
            std::string text;
            {
                std::lock_guard<std::mutex> lock(g_callLogMutex);
                for (const CallLogEntry &entry : g_callLog)
                {
                    char line[512] = {};
                    std::snprintf(line, sizeof(line),
                                  "[%06" PRIu64 "] %s+0x%" PRIX64 " x0=0x%" PRIX64 " x1=0x%" PRIX64
                                  " x2=0x%" PRIX64 " x3=0x%" PRIX64 " x4=0x%" PRIX64 " x5=0x%" PRIX64
                                  " x6=0x%" PRIX64 " x7=0x%" PRIX64 " LR=0x%" PRIX64 " SP=0x%" PRIX64,
                                  entry.counter, state.module.c_str(), entry.offset, entry.args[0], entry.args[1],
                                  entry.args[2], entry.args[3], entry.args[4], entry.args[5], entry.args[6],
                                  entry.args[7], entry.lr, entry.sp);
                    text += line;
                    text += "\n";
                }
            }
            ImGui::SetClipboardText(text.c_str());
        }
        ImGui::SameLine();
        ImGui::Text("%zu calls logged", logSize);

        if (ImGui::BeginTable("CallLog", 7,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                              ImVec2(0, MenuLayout::ScrollPanelHeight(0.30f, 150.f))))
        {
            ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 44.0f);
            ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 88.0f);
            ImGui::TableSetupColumn("x0", ImGuiTableColumnFlags_WidthFixed, 76.0f);
            ImGui::TableSetupColumn("x1", ImGuiTableColumnFlags_WidthFixed, 76.0f);
            ImGui::TableSetupColumn("x2", ImGuiTableColumnFlags_WidthFixed, 76.0f);
            ImGui::TableSetupColumn("x3", ImGuiTableColumnFlags_WidthFixed, 76.0f);
            ImGui::TableSetupColumn("LR", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::lock_guard<std::mutex> lock(g_callLogMutex);
            for (size_t index = 0; index < g_callLog.size(); ++index)
            {
                const CallLogEntry &entry = g_callLog[index];
                ImGui::PushID(static_cast<int>(index));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%" PRIu64, entry.counter);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("+0x%" PRIX64, entry.offset);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("0x%" PRIX64, entry.args[0]);
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%" PRIX64, entry.args[1]);
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("0x%" PRIX64, entry.args[2]);
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("0x%" PRIX64, entry.args[3]);
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("0x%" PRIX64, entry.lr);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::TextDisabled("x4-x7 and SP are also captured; use Copy all for the full argument list.");

        // ---------- IDA-style disassembler ----------
        ImGui::Separator();
        if (ImGui::CollapsingHeader("Disassembler (IDA-style)"))
        {
            static char saveName[128] = {};
            static std::string saveStatus;

            ImGui::TextDisabled("Disassembles ALL executable segments (IDA .lst format). UI preview capped at 50k lines.");
            if (g_disasmBusy)
            {
                ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Disassembling %s ...", module.name.c_str());
            }
            else if (ImGui::Button("Disassemble FULL lib", ImVec2(-1, 0)))
            {
                saveStatus.clear();
                g_disasmBusy = true;
                std::thread([module]()
                {
                    disassembleFullLib(module, 50000); // UI preview cap
                    g_disasmBusy = false;
                }).detach();
            }

            if (!g_disasm.empty() && !g_disasmBusy)
            {
                ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", g_disasmStatus.c_str());

                ImGui::InputText("Save as (file name)##dis", saveName, sizeof(saveName));
                if (saveName[0] == '\0')
                    std::snprintf(saveName, sizeof(saveName), "%s_disasm.lst", module.name.c_str());
                ImGui::TextDisabled("Saved to /sdcard/Android/data/<pkg>/files/ as IDA-style .lst");
                if (ImGui::Button("Save FULL .lst to file", ImVec2(-1, 0)))
                {
                    g_disasmBusy = true;
                    std::string nameCopy = saveName;
                    std::thread([module, nameCopy]()
                    {
                        std::string outPath;
                        if (saveFullDisassembly(module, nameCopy, outPath))
                            g_disasmStatus = "Saved: " + outPath;
                        else
                            g_disasmStatus = "Save failed: " + outPath;
                        g_disasmBusy = false;
                    }).detach();
                }

                // ------- Runtime API dumper (sister of the runtime dumper) -------
                static char dumpName[128] = {};
                static std::string dumpStatus;
                if (dumpName[0] == '\0')
                    std::snprintf(dumpName, sizeof(dumpName), "%s_runtime.csv", module.name.c_str());
                ImGui::InputText("Dumper file (csv)##som", dumpName, sizeof(dumpName));
                if (ImGui::Button("Dump runtime API calls", ImVec2(-1, 0)))
                {
                    std::string nameCopy = dumpName;
                    std::thread([module, nameCopy]()
                    {
                        std::string outPath;
                        if (saveRuntimeDumper(module, nameCopy, outPath))
                            dumpStatus = "Dumped: " + outPath;
                        else
                            dumpStatus = "Dump failed: " + outPath;
                    }).detach();
                }
                if (!dumpStatus.empty())
                    ImGui::TextWrapped("%s", dumpStatus.c_str());

                // ------- String decryption -------
                if (ImGui::Button("Decrypt strings in lib", ImVec2(-1, 0)))
                {
                    g_stringsBusy = true;
                    std::thread([module]()
                    {
                        decryptStringsInModule(module);
                        g_stringsBusy = false;
                    }).detach();
                }
                if (g_stringsBusy)
                    ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Decrypting ...");
                else if (!g_stringsStatus.empty())
                    ImGui::TextWrapped("%s", g_stringsStatus.c_str());

                if (ImGui::CollapsingHeader("Decrypted strings") && !g_strings.empty())
                {
                    if (ImGui::BeginTable("Strs", 3,
                                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                                          ImVec2(0, 180)))
                    {
                        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                        ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 80.0f);
                        ImGui::TableSetupColumn("Plaintext", ImGuiTableColumnFlags_WidthStretch);
                        ImGui::TableHeadersRow();
                        size_t cap = g_strings.size() < 200 ? g_strings.size() : 200;
                        for (size_t i = 0; i < cap; ++i)
                        {
                            const DecryptedString &s2 = g_strings[i];
                            ImGui::PushID(static_cast<int>(i));
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::Text("0x%08" PRIX64, s2.offset);
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextDisabled("%s", s2.method.c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::TextUnformatted(s2.plaintext.c_str());
                            ImGui::PopID();
                        }
                        ImGui::EndTable();
                    }
                }

                if (ImGui::BeginTable("Disasm", 3,
                                      ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                                      ImVec2(0, 240)))
                {
                    ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
                    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableHeadersRow();
                    for (size_t i = 0; i < g_disasm.size(); ++i)
                    {
                        const DisasmLine &line = g_disasm[i];
                        ImGui::PushID(static_cast<int>(i));
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("+0x%08" PRIX64, line.offset);
                        ImGui::TableSetColumnIndex(1);
                        ImGui::TextDisabled("%s", line.bytes.c_str());
                        ImGui::TableSetColumnIndex(2);
                        ImGui::TextUnformatted(line.text.c_str());
                        ImGui::PopID();
                    }
                    ImGui::EndTable();
                }
            }
            else if (!g_disasmStatus.empty() && !g_disasmBusy)
            {
                ImGui::TextWrapped("%s", g_disasmStatus.c_str());
            }
        }
    }
} // namespace SoMonitor
