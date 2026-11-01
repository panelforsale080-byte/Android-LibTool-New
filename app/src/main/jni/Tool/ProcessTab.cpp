#include "Tool/ProcessTab.h"

#include "Il2cpp/Il2cpp.h"
#include "Tool/Tool.h"
#include "imgui/imgui.h"

#include <thread>

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
#include <sys/stat.h>
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

    std::string selfPackageName()
    {
        std::string name = executableName(readFileLine("/proc/self/cmdline"));
        return name.empty() ? std::string("app") : name;
    }

    bool ensureDirectory(const std::string &path)
    {
        if (path.empty())
            return false;
        std::string current;
        for (size_t i = 0; i < path.size(); ++i)
        {
            current.push_back(path[i]);
            if (path[i] != '/' || current.size() <= 1)
                continue;
            if (mkdir(current.c_str(), 0770) != 0 && errno != EEXIST)
                return false;
        }
        if (mkdir(path.c_str(), 0770) != 0 && errno != EEXIST)
            return false;
        return true;
    }

    std::string saveMapsReport(int pid, const std::string &processName, const std::vector<MappingInfo> &mappings,
                               const std::string &mapsError)
    {
        const std::string directory = "/sdcard/Android/data/" + selfPackageName() + "/files";
        if (!ensureDirectory(directory))
            return "Cannot create " + directory;

        const std::string path = directory + "/process-" + std::to_string(pid) + "-maps.txt";
        FILE *file = std::fopen(path.c_str(), "w");
        if (!file)
            return std::string("Cannot write ") + path + ": " + std::strerror(errno);

        std::fprintf(file, "process: %s\n", processName.c_str());
        std::fprintf(file, "pid: %d\n", pid);
        std::fprintf(file, "source: /proc/%d/maps\n", pid);
        std::fprintf(file, "note: library path, range, file offset, and permissions only\n");
        if (!mapsError.empty())
            std::fprintf(file, "status: %s\n", mapsError.c_str());
        std::fprintf(file, "\nlibrary\tstart\tend\toffset\tperms\n");
        for (const MappingInfo &mapping : mappings)
        {
            const uint64_t base = moduleBase(mappings, mapping.path);
            const uint64_t offset = base == 0 ? 0 : mapping.start - base;
            std::fprintf(file, "%s\t%s\t%s\t%s\t%s\n", mapping.path.c_str(), address(mapping.start).c_str(),
                         address(mapping.end).c_str(), address(offset).c_str(), mapping.permissions.c_str());
        }
        std::fclose(file);
        return "Saved " + path + " (" + std::to_string(mappings.size()) + " .so regions)";
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
        static std::string saveStatus;
        static char manualPidInput[32] = {};
        static std::string manualPidStatus;
        static bool isDumping = false;
        static float dumpProgress = 0.0f;
        static char dumpStatus[256] = "Ready";
        static char currentAssembly[128] = "";

        auto startOwnDump = [&]() -> bool {
            if (isDumping || !Il2cpp::IsDumperReady())
                return false;

            isDumping = true;
            dumpProgress = 0.0f;
            std::snprintf(dumpStatus, sizeof(dumpStatus), "Starting...");
            const std::string directory = "/sdcard/Android/data/" + selfPackageName() + "/files";
            ensureDirectory(directory);
            const std::string outputPath = directory + "/dump.cs";
            std::thread([outputPath]() {
                const bool success = Il2cpp::Dump(outputPath, [](const Il2cpp::DumpProgress &progress) {
                    dumpProgress = progress.progress;
                    std::snprintf(dumpStatus, sizeof(dumpStatus), "Processing: %d/%d classes",
                                  progress.currentClassIndex, progress.totalClasses);
                    std::strncpy(currentAssembly, progress.currentAssembly.c_str(), sizeof(currentAssembly) - 1);
                    currentAssembly[sizeof(currentAssembly) - 1] = '\0';
                });
                isDumping = false;
                if (success)
                {
                    std::snprintf(dumpStatus, sizeof(dumpStatus), "Wrote %s", outputPath.c_str());
                    Tool::AddNotification("Success", "Wrote " + outputPath, true);
                }
                else
                {
                    std::snprintf(dumpStatus, sizeof(dumpStatus), "Dump failed");
                    Tool::AddNotification("Failed", "Dump failed!", false);
                }
            }).detach();
            manualPidStatus = "Dump started.";
            return true;
        };

        auto selectPid = [&](int pid) {
            selectedPid = pid;
            selectedProcess.clear();
            for (const ProcessInfo &process : processes)
            {
                if (process.pid == pid)
                {
                    selectedProcess = process.name;
                    break;
                }
            }
            if (selectedProcess.empty())
            {
                const std::string processPath = std::string("/proc/") + std::to_string(pid);
                selectedProcess = executableName(readFileLine(processPath + "/cmdline"));
                if (selectedProcess.empty())
                    selectedProcess = readFileLine(processPath + "/comm");
                if (selectedProcess.empty())
                    selectedProcess = "pid-" + std::to_string(pid);
            }

            selectedMappings.clear();
            const MapsScanResult scan = scanSharedLibraries(selectedPid);
            mapsError = scan.error;
            if (scan.readable)
                selectedMappings = scan.mappings;
            else
                selectedMappings.clear();

            if (selectedPid == getpid())
                manualPidStatus = "Own PID selected. Press Dump dump.cs to dump.";
            else
                manualPidStatus = "Other PID selected — maps/report only.";
        };

        if (!hasScanned)
        {
            processes = scanProcesses(unreadableCount);
            hasScanned = true;
            std::snprintf(manualPidInput, sizeof(manualPidInput), "%d", getpid());
            selectedPid = getpid();
            selectedProcess = selfPackageName() + "  (this process)";
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
        ImGui::SameLine();
        ImGui::Checkbox("Auto refresh##processes", &autoRefresh);
        ImGui::SameLine();
        ImGui::Text("%zu visible processes", processes.size());

        ImGui::InputText("Filter##processes", filter, sizeof(filter));
        ImGui::TextDisabled("Only .so files under /data/app/ are included. Select a process to inspect mappings.");
        ImGui::Separator();
        ImGui::Text("Manual PID");
        ImGui::SetNextItemWidth(160.0f);
        ImGui::InputText("##manualPid", manualPidInput, sizeof(manualPidInput),
                         ImGuiInputTextFlags_CharsDecimal);
        ImGui::SameLine();
        if (ImGui::Button("Use PID##manual"))
        {
            const int pid = std::atoi(manualPidInput);
            if (pid <= 0)
                manualPidStatus = "Enter a valid PID.";
            else
                selectPid(pid);
        }
        ImGui::SameLine();
        if (ImGui::Button("Use this PID##manualSelf"))
        {
            std::snprintf(manualPidInput, sizeof(manualPidInput), "%d", getpid());
            selectPid(getpid());
        }
        ImGui::TextDisabled("Dump only runs in this process (%d). No auto dump — press Dump dump.cs.", getpid());
        if (!manualPidStatus.empty())
            ImGui::TextWrapped("%s", manualPidStatus.c_str());
        if (unreadableCount > 0)
            ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.25f, 1.0f),
                               "%zu process entries could not be read due to host permissions.", unreadableCount);
        ImGui::Separator();

        if (ImGui::BeginTable("ProcessList", 2,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                              ImVec2(0, selectedPid >= 0 ? ImGui::GetContentRegionAvail().y * 0.42f : 0)))
        {
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 90.0f);
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
                const std::string rowLabel =
                    process.pid == getpid() ? process.name + "  (this process)" : process.name;
                if (ImGui::Selectable(rowLabel.c_str(), selectedPid == process.pid,
                                      ImGuiSelectableFlags_SpanAllColumns))
                {
                    std::snprintf(manualPidInput, sizeof(manualPidInput), "%d", process.pid);
                    selectPid(process.pid);
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
        if (ImGui::Button("Save maps report##processes"))
            saveStatus = saveMapsReport(selectedPid, selectedProcess, selectedMappings, mapsError);
        ImGui::SameLine();
        ImGui::Text("%zu .so regions", selectedMappings.size());
        if (!saveStatus.empty())
            ImGui::TextWrapped("%s", saveStatus.c_str());

        if (selectedPid != getpid())
        {
            ImGui::TextDisabled("Dump dump.cs is only available on (this process). Other PIDs are maps/report only.");
        }

        if (selectedPid == getpid())
        {
            ImGui::Separator();
            if (!Il2cpp::IsDumperReady())
            {
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Il2Cpp not ready in this process.");
            }
            else if (isDumping)
            {
                ImGui::Button("Dumping...##process", ImVec2(-1, 0));
                ImGui::ProgressBar(dumpProgress, ImVec2(-1.0f, 0.0f));
                ImGui::Text("Status: %s", dumpStatus);
                ImGui::Text("Assembly: %s", currentAssembly);
            }
            else if (ImGui::Button("Dump dump.cs##process", ImVec2(-1, 0)))
            {
                startOwnDump();
            }
            if (std::strcmp(dumpStatus, "Ready") != 0)
                ImGui::TextWrapped("%s", dumpStatus);
        }

        if (ImGui::CollapsingHeader("Current .so mappings", ImGuiTreeNodeFlags_DefaultOpen))
        {
            if (ImGui::BeginTable("SharedLibraryMappings", 5,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                                  ImVec2(0, 170)))
            {
                ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Start", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthFixed, 130.0f);
                ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 110.0f);
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
