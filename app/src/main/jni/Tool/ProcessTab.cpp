#include "Tool/ProcessTab.h"

#include "Menu/MenuLayout.h"
#include "imgui/imgui.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

namespace
{
    struct ProcessInfo
    {
        int pid;
        std::string name;
    };

    struct MappingInfo
    {
        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t fileOffset = 0;
        std::string permissions;
        std::string path;
    };

    struct MapsScanResult
    {
        bool readable = false;
        std::string error;
        std::vector<MappingInfo> mappings;
    };

    std::string readFileLine(const std::string &path)
    {
        FILE *file = std::fopen(path.c_str(), "rb");
        if (!file)
            return {};

        char buffer[4096] = {};
        const size_t bytesRead = std::fread(buffer, 1, sizeof(buffer) - 1, file);
        std::fclose(file);
        if (bytesRead == 0)
            return {};

        buffer[bytesRead] = '\0';
        for (size_t i = 0; i < bytesRead; ++i)
        {
            if (buffer[i] == '\0' || buffer[i] == '\n' || buffer[i] == '\r')
            {
                buffer[i] = '\0';
                break;
            }
        }
        return std::string(buffer);
    }

    std::string executableName(const std::string &command)
    {
        if (command.empty())
            return {};

        const size_t slash = command.find_last_of('/');
        return slash == std::string::npos ? command : command.substr(slash + 1);
    }

    bool isPidDirectory(const char *name)
    {
        if (!name || *name == '\0')
            return false;

        for (const char *cursor = name; *cursor; ++cursor)
        {
            if (!std::isdigit(static_cast<unsigned char>(*cursor)))
                return false;
        }
        return true;
    }

    bool isSharedLibrary(const std::string &path)
    {
        constexpr const char *appDataPrefix = "/data/app/";
        if (path.compare(0, std::strlen(appDataPrefix), appDataPrefix) != 0)
            return false;

        const size_t deletedSuffix = path.find(" (deleted)");
        const std::string libraryPath = path.substr(0, deletedSuffix);
        return libraryPath.find(".so") != std::string::npos;
    }

    std::string trimLeft(std::string value)
    {
        const size_t first = value.find_first_not_of(" \t");
        return first == std::string::npos ? std::string() : value.substr(first);
    }

    bool parseHexRange(const std::string &value, uint64_t &start, uint64_t &end)
    {
        const size_t separator = value.find('-');
        if (separator == std::string::npos)
            return false;

        char *startEnd = nullptr;
        char *endEnd = nullptr;
        start = std::strtoull(value.substr(0, separator).c_str(), &startEnd, 16);
        end = std::strtoull(value.substr(separator + 1).c_str(), &endEnd, 16);
        return startEnd && *startEnd == '\0' && endEnd && *endEnd == '\0' && end > start;
    }

    bool parseMappingLine(const std::string &line, MappingInfo &mapping)
    {
        std::istringstream stream(line);
        std::string addressRange;
        std::string device;
        uint64_t inode = 0;
        if (!(stream >> addressRange >> mapping.permissions >> std::hex >> mapping.fileOffset >> device >> inode))
            return false;
        if (!parseHexRange(addressRange, mapping.start, mapping.end))
            return false;

        std::string path;
        std::getline(stream, path);
        mapping.path = trimLeft(path);
        return !mapping.path.empty() && isSharedLibrary(mapping.path);
    }

    std::string filePathForLibrary(const std::string &path)
    {
        const size_t deletedSuffix = path.find(" (deleted)");
        return path.substr(0, deletedSuffix);
    }

    MapsScanResult scanSharedLibraries(int pid)
    {
        MapsScanResult result;
        const std::string mapsPath = std::string("/proc/") + std::to_string(pid) + "/maps";
        FILE *file = std::fopen(mapsPath.c_str(), "rb");
        if (!file)
        {
            const int errorCode = errno;
            result.error = std::string("Cannot read ") + mapsPath + ": " + std::strerror(errorCode) +
                           " (Android may restrict maps access for another UID/process)";
            return result;
        }

        char line[8192] = {};
        while (std::fgets(line, sizeof(line), file))
        {
            MappingInfo mapping;
            if (parseMappingLine(line, mapping))
                result.mappings.push_back(std::move(mapping));
        }
        if (std::ferror(file))
            result.error = std::string("Error while reading ") + mapsPath;
        else
            result.readable = true;
        std::fclose(file);
        if (result.readable && result.mappings.empty())
            result.error = "The maps file is readable, but no /data/app/*.so mappings were found for this process.";
        return result;
    }

    std::vector<ProcessInfo> scanProcesses(size_t &unreadableCount)
    {
        unreadableCount = 0;
        std::vector<ProcessInfo> processes;
        DIR *procDirectory = opendir("/proc");
        if (!procDirectory)
            return processes;

        while (dirent *entry = readdir(procDirectory))
        {
            if (!isPidDirectory(entry->d_name))
                continue;

            const int pid = std::atoi(entry->d_name);
            if (pid <= 0)
                continue;

            const std::string processPath = std::string("/proc/") + entry->d_name;
            std::string name = executableName(readFileLine(processPath + "/cmdline"));
            if (name.empty())
                name = readFileLine(processPath + "/comm");

            if (name.empty())
            {
                ++unreadableCount;
                continue;
            }
            processes.push_back({pid, std::move(name)});
        }
        closedir(procDirectory);

        std::sort(processes.begin(), processes.end(), [](const ProcessInfo &left, const ProcessInfo &right) {
            return left.pid < right.pid;
        });
        return processes;
    }

    uint64_t alignDown(uint64_t value, uint64_t pageSize)
    {
        return value & ~(pageSize - 1);
    }

    uint64_t moduleBase(const std::vector<MappingInfo> &mappings, const std::string &library)
    {
        uint64_t pageSize = static_cast<uint64_t>(sysconf(_SC_PAGESIZE));
        if (pageSize == 0 || (pageSize & (pageSize - 1)) != 0)
            pageSize = 4096;

        const std::string filePath = filePathForLibrary(library);
        const int file = open(filePath.c_str(), O_RDONLY | O_CLOEXEC);
        if (file >= 0)
        {
            unsigned char ident[EI_NIDENT] = {};
            const ssize_t identBytes = pread(file, ident, sizeof(ident), 0);
            if (identBytes == static_cast<ssize_t>(sizeof(ident)) && ident[EI_MAG0] == ELFMAG0 &&
                ident[EI_MAG1] == ELFMAG1 && ident[EI_MAG2] == ELFMAG2 && ident[EI_MAG3] == ELFMAG3)
            {
                uint64_t base = UINT64_MAX;
                if (ident[EI_CLASS] == ELFCLASS64)
                {
                    Elf64_Ehdr header = {};
                    if (pread(file, &header, sizeof(header), 0) == static_cast<ssize_t>(sizeof(header)))
                    {
                        for (uint16_t index = 0; index < header.e_phnum; ++index)
                        {
                            Elf64_Phdr program = {};
                            const off_t position =
                                static_cast<off_t>(header.e_phoff + index * header.e_phentsize);
                            if (pread(file, &program, sizeof(program), position) != static_cast<ssize_t>(sizeof(program)) ||
                                program.p_type != PT_LOAD)
                                continue;

                            for (const MappingInfo &mapping : mappings)
                            {
                                if (mapping.path != library)
                                    continue;
                                if (alignDown(mapping.fileOffset, pageSize) != alignDown(program.p_offset, pageSize))
                                    continue;
                                const uint64_t virtualAddress = alignDown(program.p_vaddr, pageSize);
                                if (mapping.start >= virtualAddress)
                                    base = std::min(base, mapping.start - virtualAddress);
                            }
                        }
                    }
                }
                else if (ident[EI_CLASS] == ELFCLASS32)
                {
                    Elf32_Ehdr header = {};
                    if (pread(file, &header, sizeof(header), 0) == static_cast<ssize_t>(sizeof(header)))
                    {
                        for (uint16_t index = 0; index < header.e_phnum; ++index)
                        {
                            Elf32_Phdr program = {};
                            const off_t position =
                                static_cast<off_t>(header.e_phoff + index * header.e_phentsize);
                            if (pread(file, &program, sizeof(program), position) != static_cast<ssize_t>(sizeof(program)) ||
                                program.p_type != PT_LOAD)
                                continue;

                            for (const MappingInfo &mapping : mappings)
                            {
                                if (mapping.path != library)
                                    continue;
                                if (alignDown(mapping.fileOffset, pageSize) != alignDown(program.p_offset, pageSize))
                                    continue;
                                const uint64_t virtualAddress = alignDown(program.p_vaddr, pageSize);
                                if (mapping.start >= virtualAddress)
                                    base = std::min(base, mapping.start - virtualAddress);
                            }
                        }
                    }
                }
                close(file);
                if (base != UINT64_MAX)
                    return base;
            }
            close(file);
        }

        // Fallback for deleted/unreadable ELF files: the first mapping is still
        // useful as a display value, but the UI labels it as a fallback base.
        uint64_t fallback = UINT64_MAX;
        for (const MappingInfo &mapping : mappings)
        {
            if (mapping.path == library)
                fallback = std::min(fallback, mapping.start);
        }
        return fallback == UINT64_MAX ? 0 : fallback;
    }

    std::string address(uint64_t value)
    {
        char buffer[32] = {};
        std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
        return buffer;
    }
} // namespace

namespace ProcessTab
{
    void Draw()
    {
        static std::vector<ProcessInfo> processes;
        static size_t unreadableCount = 0;
        static bool hasScanned = false;
        static bool autoRefresh = false;
        static char filter[128] = {};

        static int selectedPid = -1;
        static std::string selectedProcess;
        static std::vector<MappingInfo> selectedMappings;
        static std::string mapsError;

        if (!hasScanned)
        {
            processes = scanProcesses(unreadableCount);
            hasScanned = true;
        }

        if (autoRefresh)
        {
            static float elapsed = 0.0f;
            elapsed += ImGui::GetIO().DeltaTime;
            if (elapsed >= 2.0f)
            {
                processes = scanProcesses(unreadableCount);
                elapsed = 0.0f;
            }
        }

        if (ImGui::Button("Refresh##processes"))
            processes = scanProcesses(unreadableCount);
        if (!MenuLayout::IsNarrowLayout())
        {
            ImGui::SameLine();
            ImGui::Checkbox("Auto refresh##processes", &autoRefresh);
            ImGui::SameLine();
            ImGui::Text("%zu visible processes", processes.size());
        }
        else
        {
            ImGui::Checkbox("Auto refresh##processes", &autoRefresh);
            ImGui::Text("%zu visible processes", processes.size());
        }

        ImGui::InputText("Filter##processes", filter, sizeof(filter));
        ImGui::TextDisabled("Only .so files under /data/app/ are included. Select a process to inspect mappings.");
        if (unreadableCount > 0)
            ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.25f, 1.0f),
                               "%zu process entries could not be read due to host permissions.", unreadableCount);
        ImGui::Separator();

        const float processTableH = selectedPid >= 0
                                        ? MenuLayout::ScrollPanelHeight(0.38f, 140.f)
                                        : MenuLayout::ScrollPanelHeight(0.72f, 180.f);
        if (ImGui::BeginTable("ProcessList", 2,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                              ImVec2(0, processTableH)))
        {
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed,
                                    MenuLayout::IsNarrowLayout() ? 64.0f : 90.0f);
            ImGui::TableSetupColumn("Process name", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            const std::string search = filter;
            for (const ProcessInfo &process : processes)
            {
                if (!search.empty() && std::to_string(process.pid).find(search) == std::string::npos &&
                    process.name.find(search) == std::string::npos)
                    continue;

                ImGui::PushID(process.pid);
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%d", process.pid);
                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(process.name.c_str(), selectedPid == process.pid,
                                      ImGuiSelectableFlags_SpanAllColumns))
                {
                    selectedPid = process.pid;
                    selectedProcess = process.name;
                    selectedMappings.clear();
                    const MapsScanResult scan = scanSharedLibraries(selectedPid);
                    mapsError = scan.error;
                    if (scan.readable)
                        selectedMappings = scan.mappings;
                    else
                        selectedMappings.clear();
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        if (selectedPid < 0)
            return;

        ImGui::Separator();
        ImGui::Text("Selected process: %s (PID %d)", selectedProcess.c_str(), selectedPid);
        ImGui::TextDisabled("This tab observes /proc/%d/maps only; it does not read values or change target memory.",
                            selectedPid);
        if (!mapsError.empty())
            ImGui::TextColored(selectedMappings.empty() ? ImVec4(1.0f, 0.55f, 0.2f, 1.0f)
                                                         : ImVec4(1.0f, 0.35f, 0.35f, 1.0f),
                               "%s", mapsError.c_str());

        if (ImGui::Button("Rescan .so mappings##processes"))
        {
            const MapsScanResult scan = scanSharedLibraries(selectedPid);
            mapsError = scan.error;
            if (scan.readable)
                selectedMappings = scan.mappings;
            else
                selectedMappings.clear();
        }
        ImGui::SameLine();
        ImGui::Text("%zu .so regions", selectedMappings.size());

        if (ImGui::CollapsingHeader("Current .so mappings", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (ImGui::BeginTable("SharedLibraryMappings", 5,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                                  ImVec2(0, MenuLayout::ScrollPanelHeight(0.42f, 150.f)))
            {
                ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Start", ImGuiTableColumnFlags_WidthFixed,
                                        MenuLayout::IsNarrowLayout() ? 96.0f : 130.0f);
                ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthFixed,
                                        MenuLayout::IsNarrowLayout() ? 96.0f : 130.0f);
                ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed,
                                        MenuLayout::IsNarrowLayout() ? 88.0f : 110.0f);
                ImGui::TableSetupColumn("Perms", ImGuiTableColumnFlags_WidthFixed, 55.0f);
                ImGui::TableHeadersRow();

                for (const MappingInfo &mapping : selectedMappings)
                {
                    const uint64_t base = moduleBase(selectedMappings, mapping.path);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::TextUnformatted(mapping.path.c_str());
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(address(mapping.start).c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(address(mapping.end).c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(address(base == 0 ? 0 : mapping.start - base).c_str());
                    ImGui::TableSetColumnIndex(4);
                    ImGui::TextUnformatted(mapping.permissions.c_str());
                }
                ImGui::EndTable();
            }
        }
    }
} // namespace ProcessTab
