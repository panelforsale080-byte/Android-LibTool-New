#include "Tool/SoMonitor.h"
#include "Tool/SoMonitorTrace.h"

#include "Menu/MenuLayout.h"
#include "imgui/imgui.h"
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

    // ---- legacy symbol helper (disassembler labels) ----

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

    SoTraceModule toTraceModule(const ModuleInfo &module)
    {
        SoTraceModule out;
        out.name = module.name;
        out.path = module.path;
        out.base = module.base;
        out.size = module.size;
        out.execRanges.reserve(module.execRanges.size());
        for (const ExecRange &range : module.execRanges)
            out.execRanges.push_back({range.begin, range.end});
        return out;
    }

    void startRuntimeTrace(const ModuleInfo &module)
    {
        refreshModules();
        for (const ModuleInfo &m : g_modules)
        {
            if (m.path == module.path || m.name == module.name)
            {
                SoMonitorTrace::Start(toTraceModule(m));
                return;
            }
        }
        SoMonitorTrace::Start(toTraceModule(module));
    }
} // namespace

namespace SoMonitor
{
    void Draw()
    {
        if (!g_modulesLoaded)
            refreshModules();

        const SoTraceState traceState = SoMonitorTrace::GetState();

        static int selectedModule = -1;
        static bool requestStart = false;

        if (ImGui::Button("Refresh modules##som"))
        {
            SoMonitorTrace::Stop();
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
            "Step 1: pick the game lib — runtime call hooks (like IL2CPP Tracer) + PC sampler.");
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
            ImGui::TextDisabled("Step 1: select the game's main .so above — runtime trace starts automatically.");
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
            {
                ImGui::Text("%s  =  %s + %s", convAddr, hex(module.base).c_str(), convOff);
                static std::string hookStatus;
                if (ImGui::Button("Hook this offset##tracehook"))
                {
                    if (SoMonitorTrace::HookOffset(vo, hookStatus))
                        hookStatus = "Hooked +0x" + hex(vo).substr(2);
                    else if (hookStatus.empty())
                        hookStatus = "Hook failed.";
                }
                if (!hookStatus.empty())
                    ImGui::TextWrapped("%s", hookStatus.c_str());
            }
        }
        ImGui::Separator();

        if (requestStart && !traceState.starting)
        {
            requestStart = false;
            if (!traceState.active || traceState.base != module.base || traceState.moduleName != module.name)
                startRuntimeTrace(module);
        }

        if (traceState.starting || traceState.hookInstalling)
        {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%s", traceState.status.c_str());
            if (traceState.hookInstallTotal > 0)
            {
                const float progress =
                    static_cast<float>(traceState.hookInstallDone) / static_cast<float>(traceState.hookInstallTotal);
                ImGui::ProgressBar(progress, ImVec2(-1, 0),
                                   (std::to_string(traceState.hookInstallDone) + "/" +
                                    std::to_string(traceState.hookInstallTotal) + " hooks")
                                       .c_str());
            }
            ImGui::TextDisabled("Large libs install hooks in batches — PC sampler runs meanwhile.");
        }
        else if (traceState.active && traceState.base == module.base && traceState.moduleName == module.name)
        {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", traceState.status.c_str());
            ImGui::TextDisabled(
                "%zu threads | %zu hooks (%zu gum + %zu dobby) | %zu slots | %" PRIu64 " hits | call:%" PRIu64
                " sample:%" PRIu64 " rounds:%" PRIu64,
                traceState.threadCount, traceState.hookedCount, traceState.interceptorCount, traceState.dobbyCount,
                traceState.insnSlots, traceState.totalExecutions, traceState.hookHits, traceState.sampleHits,
                traceState.sampleRounds);
            if (traceState.hookCap > 0)
                ImGui::TextDisabled("Hook cap for this lib size: %zu", traceState.hookCap);
            if (traceState.hookFailed > 0)
                ImGui::TextDisabled("%zu hook installs failed (cap or unsupported insn)", traceState.hookFailed);
            if (traceState.totalExecutions == 0 && traceState.sampleRounds > 100)
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f),
                                   "0 hits — play the game, or use Hook this offset on a known function.");
            else if (traceState.sampleRounds == 0)
                ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f), "Starting hooks + sampler ...");
            if (ImGui::Button("Stop runtime trace", ImVec2(-1, 0)))
                SoMonitorTrace::Stop();
        }
        else
        {
            ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.4f, 1.0f), "%s", traceState.status.c_str());
            if (!traceState.starting && ImGui::Button("Start runtime trace", ImVec2(-1, 0)))
                startRuntimeTrace(module);
        }

        ImGui::TextDisabled(
            "Large libs (6–10 MB): lazy mode, batched hooks, capped count. PC sampler = hot insn lines.");
        ImGui::Separator();

        static bool hideZeroHits = true;
        static bool sortByHits = true;
        static int minHits = 0;
        static char traceFilter[64] = {};
        static char traceCsvName[128] = {};
        static std::string traceExportStatus;

        ImGui::Checkbox("Hide 0-hit instructions", &hideZeroHits);
        ImGui::SameLine();
        ImGui::Checkbox("Sort by hits", &sortByHits);
        ImGui::SetNextItemWidth(120.f);
        ImGui::InputInt("Min hits##trace", &minHits);
        if (minHits < 0)
            minHits = 0;
        ImGui::InputText("Filter offset/mnemonic##trace", traceFilter, sizeof(traceFilter));

        if (ImGui::Button("Clear hit counts"))
            SoMonitorTrace::ClearHits();
        ImGui::SameLine();
        if (traceCsvName[0] == '\0')
            std::snprintf(traceCsvName, sizeof(traceCsvName), "%s_trace.csv", module.name.c_str());
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("Export CSV##trace", traceCsvName, sizeof(traceCsvName));
        if (ImGui::Button("Export trace CSV", ImVec2(-1, 0)))
        {
            std::string nameCopy = traceCsvName;
            std::thread([nameCopy]()
            {
                std::string outPath;
                if (SoMonitorTrace::ExportCsv(nameCopy, outPath))
                    traceExportStatus = "Exported: " + outPath;
                else
                    traceExportStatus = "Export failed: " + outPath;
            }).detach();
        }
        if (!traceExportStatus.empty())
            ImGui::TextWrapped("%s", traceExportStatus.c_str());

        std::vector<SoTraceHitEntry> hits =
            SoMonitorTrace::GetSnapshot(hideZeroHits, static_cast<uint64_t>(minHits), sortByHits);
        if (traceFilter[0] != '\0')
        {
            std::vector<SoTraceHitEntry> filtered;
            filtered.reserve(hits.size());
            for (const SoTraceHitEntry &hit : hits)
            {
                char offBuf[32] = {};
                std::snprintf(offBuf, sizeof(offBuf), "%" PRIX64, hit.offset);
                if (std::string(offBuf).find(traceFilter) != std::string::npos ||
                    hit.mnemonic.find(traceFilter) != std::string::npos)
                    filtered.push_back(hit);
            }
            hits = std::move(filtered);
        }

        ImGui::Text("%zu instruction rows shown", hits.size());

        if (ImGui::BeginTable("TraceHits", 3,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                              ImVec2(0, MenuLayout::ScrollPanelHeight(0.30f, 150.f))))
        {
            ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableHeadersRow();

            const size_t cap = hits.size() < 2000 ? hits.size() : 2000;
            for (size_t index = 0; index < cap; ++index)
            {
                const SoTraceHitEntry &hit = hits[index];
                ImGui::PushID(static_cast<int>(index));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("+0x%08" PRIX64, hit.offset);
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(hit.mnemonic.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%" PRIu64, hit.hits);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if (hits.size() > 2000)
            ImGui::TextDisabled("UI capped at 2000 rows — export CSV for full list.");

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
