#include "Tool.h"
#include "Includes/obfuscate.h"
#include "Menu/MenuLayout.h"
#include "Il2cpp/Il2cpp.h"
#include "Il2cpp/il2cpp-tabledefs.h"
#include "Tool/Frida.h"
#include "Tool/Keyboard.h"
#include "Tool/Util.h"
#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include <future>
#include <set>
#include <algorithm>
#include <array>
#include <chrono>
#include <mutex>
#include <fstream>

extern ImVec2 initialScreenSize;
extern std::unordered_map<void *, HookerData> hookerMap;
extern std::mutex hookerMtx;
extern bool collapsed;

std::vector<Il2CppImage *> g_Images;

CircularBuffer<HookerTrace> HookerData::visited{50};
std::unordered_map<Il2CppClass *, std::set<Il2CppObject *>> HookerData::collectSet{};

namespace Tool
{
    struct CallData
    {
        MethodInfo *method;
        Il2CppObject *thiz;
        Il2CppArray<Il2CppObject *> *params;
    };

    struct ParamValue
    {
        std::string value;
        Il2CppObject *object;
    };

    std::vector<Il2CppClass *> tracer;

    std::vector<ClassesTab> classesTabs;

    struct Notification
    {
        std::string title;
        std::string message;
        float duration;
        bool success;
        float alpha = 1.0f;
    };
    std::vector<Notification> notifications;
    std::mutex notifyMtx;

    void AddNotification(const std::string &title, const std::string &message, bool success, float duration)
    {
        std::lock_guard<std::mutex> lock(notifyMtx);
        notifications.push_back({title, message, duration, success, 1.0f});
    }

    void DrawNotifications()
    {
        std::lock_guard<std::mutex> lock(notifyMtx);
        if (notifications.empty())
            return;

        ImGuiIO &io = ImGui::GetIO();

        // Calculate scaling based on current font size
        float fontScale = ImGui::GetFontSize() / 13.0f;
        float spacing = 6.0f * fontScale;

        // Closer to corner
        float paddingX = 15.0f * fontScale;
        float paddingY = 15.0f * fontScale;

        ImVec2 pos = ImVec2(io.DisplaySize.x - paddingX, io.DisplaySize.y - paddingY);

        for (auto it = notifications.begin(); it != notifications.end();)
        {
            it->duration -= io.DeltaTime;
            if (it->duration <= 0.0f)
            {
                it->alpha -= io.DeltaTime * 2.0f;
                if (it->alpha <= 0.0f)
                {
                    it = notifications.erase(it);
                    continue;
                }
            }

            // Calculate dynamic width based on content
            float titleWidth = ImGui::CalcTextSize(it->title.c_str()).x + 55.0f * fontScale;
            float messageWidth = ImGui::CalcTextSize(it->message.c_str()).x + 20.0f * fontScale;
            float width = std::max(titleWidth, messageWidth);
            width = std::min(width, io.DisplaySize.x * 0.85f); // Allow it to be wider if needed but not screen-filling
            width = std::max(width, 120.0f * fontScale);      // Minimum width to look good

            float height = 50.0f * fontScale;

            std::string windowId = "##notify_" + std::to_string(std::distance(notifications.begin(), it));

            ImGui::SetNextWindowPos(ImVec2(pos.x - width, pos.y - height), ImGuiCond_Always);
            ImGui::SetNextWindowSize(ImVec2(width, height));
            ImGui::SetNextWindowBgAlpha(it->alpha * 0.85f);

            ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav |
                                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoFocusOnAppearing;

            ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f * fontScale);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6 * fontScale, 3 * fontScale));
            if (ImGui::Begin(windowId.c_str(), nullptr, flags))
            {
                ImDrawList *drawList = ImGui::GetWindowDrawList();
                ImVec2 p = ImGui::GetCursorScreenPos();

                // Draw Icon Circle
                ImVec4 iconColor = it->success ? ImVec4(0.2f, 0.8f, 0.2f, it->alpha) : ImVec4(0.8f, 0.2f, 0.2f, it->alpha);
                float radius = 7.0f * fontScale;
                float textLineHeight = ImGui::GetTextLineHeight();
                ImVec2 center = ImVec2(p.x + 10 * fontScale, p.y + textLineHeight * 0.5f);
                drawList->AddCircleFilled(center, radius, ImColor(iconColor));

                // Draw checkmark or X
                float thickness = 1.5f * fontScale;
                float size = 3.5f * fontScale;
                if (it->success)
                {
                    drawList->AddLine(ImVec2(center.x - size, center.y), ImVec2(center.x - size * 0.2f, center.y + size * 0.8f), IM_COL32(255, 255, 255, it->alpha * 255), thickness);
                    drawList->AddLine(ImVec2(center.x - size * 0.2f, center.y + size * 0.8f), ImVec2(center.x + size, center.y - size * 0.8f), IM_COL32(255, 255, 255, it->alpha * 255), thickness);
                }
                else
                {
                    drawList->AddLine(ImVec2(center.x - size * 0.8f, center.y - size * 0.8f), ImVec2(center.x + size * 0.8f, center.y + size * 0.8f), IM_COL32(255, 255, 255, it->alpha * 255), thickness);
                    drawList->AddLine(ImVec2(center.x + size * 0.8f, center.y - size * 0.8f), ImVec2(center.x - size * 0.8f, center.y + size * 0.8f), IM_COL32(255, 255, 255, it->alpha * 255), thickness);
                }

                ImGui::SetCursorPosX(28 * fontScale);
                ImGui::Text("%s", it->title.c_str());

                // Close button (x)
                ImGui::SameLine(width - 18 * fontScale);
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, it->alpha), "x");

                ImGui::Separator();
                ImGui::PushTextWrapPos(width - 10 * fontScale);
                ImGui::Text("%s", it->message.c_str());
                ImGui::PopTextWrapPos();
            }
            ImGui::End();
            ImGui::PopStyleVar(2);

            pos.y -= height + spacing;
            ++it;
        }
    }

    void ConfigLoad()
    {
        LOGD(__FUNCTION__);
        try
        {
            Util::FileReader configFile("class_tabs.json");
            nlohmann::ordered_json j = nlohmann::ordered_json::parse(configFile.read());
            classesTabs = j.template get<std::vector<ClassesTab>>();
        }
        catch (nlohmann::json::exception &e)
        {
            LOGE("Failed to load class_tabs.json: %s", e.what());
            ConfigSave();
        }
    }
    void ConfigSave()
    {
        LOGD(__FUNCTION__);
        Util::FileWriter configFile("class_tabs.json");
        nlohmann::ordered_json j = classesTabs;
        configFile.write(j.dump(2, ' ').c_str());
    }
    void ConfigInit()
    {
        LOGD(__FUNCTION__);
        // check if class_tabs.json exists
        Util::FileReader config("class_tabs.json");
        if (config.exists())
        {
            ConfigLoad();
        }
        else
        {
            ConfigSave();
        }
    }

    void CalculateSomething()
    {
        constexpr auto *placeholder = "BRUH";
        int max = 10;

        for (int i = 0; i < 100; i++)
        {
            auto labelSize = ImGui::CalcTextSize(placeholder);
            ImVec2 labellPos{20, 150 + (labelSize.y * i)};
            if (labellPos.y >= ImGui::GetIO().DisplaySize.y)
            {
                max = i - 5;
                break;
            }
        }
        LOGINT(max);
        HookerData::visited = CircularBuffer<HookerTrace>(max);
    }

    void InitScreenSize()
    {
        auto Display = Il2cpp::FindClass("UnityEngine.Display");
        if (!Display)
        {
            LOGE("Failed to find class 'Display'");
            return;
        }
        auto mainDisplay = Display->invoke_static_method<Il2CppObject *>("get_main");
        if (!mainDisplay)
        {
            LOGE("Failed to get main display");
            return;
        }
        auto systemWidth = mainDisplay->invoke_method<int32_t>("get_systemWidth");
        auto systemHeight = mainDisplay->invoke_method<int32_t>("get_systemHeight");

        if (systemWidth && systemHeight)
        {
            initialScreenSize.x = systemWidth;
            initialScreenSize.y = systemHeight;
            LOGI("Screen size: %d x %d", systemWidth, systemHeight);
        }
    }

    ClassesTab &GetFirstTab()
    {
        return classesTabs[0];
    }

    ClassesTab &OpenNewTab()
    {
        ClassesTab clone;
        for (auto &c : classesTabs)
        {
            if (c.currentlyOpened)
            {
                clone.selectedImage = c.selectedImage;
                break;
            }
        }
        return classesTabs.emplace_back(clone);
    }
    ClassesTab &OpenNewTabFromClass(Il2CppClass *klass)
    {
        auto &tab = OpenNewTab();
        tab.filter = klass->getFullName();
        tab.selectedImage = klass->getImage();
        tab.FilterClasses(tab.filter);
        return tab;
    }

    std::string GetWindowRect()
    {
        char result[256] = "0|0|0|0";
        if (ImGui::GetCurrentContext())
        {
            if (ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId))
            {
                // Popups like the keypad need full access
                sprintf(result, "0|0|%d|%d", (int)ImGui::GetIO().DisplaySize.x, (int)ImGui::GetIO().DisplaySize.y);
            }
            else
            {
                ImGuiWindow *window = ImGui::FindWindowByName(OBFUSCATE("IL2CPP Tool v0.9 By mIsmanXP @ Platinmods.com | Discord : @cat.ll"));
                if (window && !collapsed)
                {
                    sprintf(result, "%d|%d|%d|%d", (int)window->Pos.x, (int)window->Pos.y, (int)window->Size.x, (int)window->Size.y);
                }
            }
        }
        return result;
    }

    std::vector<std::string> dumpPaths;
    int selectedPathIdx = 0;

    void InitDumpPaths()
    {
        if (!dumpPaths.empty())
            return;
        std::string pkg = Il2cpp::getPackageName();
        dumpPaths.push_back("/sdcard/Android/data/" + pkg + "/files");
        dumpPaths.push_back("/storage/emulated/0/Download");
        dumpPaths.push_back("/storage/emulated/0/Documents");
        dumpPaths.push_back("/storage/emulated/0/Pictures");
        dumpPaths.push_back("/sdcard/Download");
        dumpPaths.push_back("/sdcard/Documents");
        dumpPaths.push_back("/sdcard/Pictures");
    }

    void Init(Il2CppImage *image, std::vector<Il2CppImage *> images)
    {
        ConfigInit();
        InitScreenSize();
        InitDumpPaths();
        g_Images = images;
        std::sort(g_Images.begin(), g_Images.end(),
                  [](Il2CppImage *img1, Il2CppImage *img2)
                  { return std::strcmp(img1->getName(), img2->getName()) < 0; });
        classesTabs.reserve(32);
        if (classesTabs.empty())
            OpenNewTab();

        for (ClassesTab &tab : classesTabs)
        {
            tab.FilterClasses(tab.filter);
        }
#ifdef USE_FRIDA
        Frida::Init();
#endif
    }

    void Draw()
    {
        [[maybe_unused]] static auto _ = []
        {
            CalculateSomething();
            return true;
        }();
        if (ImGui::BeginTabBar("tabber", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll |
                                             ImGuiTabBarFlags_TabListPopupButton))
        {
            if (ImGui::TabItemButton("+", ImGuiTabItemFlags_NoTooltip | ImGuiTabItemFlags_Leading))
            {
                auto &tab = OpenNewTab();
                tab.FilterClasses(tab.filter);
            }
            int i = 0;
            auto it = std::begin(classesTabs);
            while (it != std::end(classesTabs))
            {
                if (!it->opened)
                {
                    LOGD("Closing %d", i);
                    it = classesTabs.erase(it);
                    if (classesTabs.empty())
                    {
                        auto &tab = OpenNewTab();
                        tab.FilterClasses(tab.filter);
                        break;
                    }
                    ConfigSave();
                }
                else
                {
                    ImGui::PushID(i);
                    it->Draw(i, true);
                    it->DrawTabMap();
                    ImGui::PopID();
                    ++it;
                    i++;
                }
            }
            ImGui::EndTabBar();
        }
    }

    void Strings()
    {
        static char filter[128] = "";
        static std::vector<std::string> strings;
        static bool externalChanged = false;

        auto searchStrings = [](const char *f)
        {
            auto StringKlass = Il2cpp::FindClass("System.String");
            if (!StringKlass)
                return;
            auto objects = Il2cpp::GC::FindObjects(StringKlass);
            strings.clear();
            for (auto obj : objects)
            {
                auto s = (Il2CppString *)obj;
                if (!s)
                    continue;
                auto str = s->to_string();
                if (f[0] == '\0' || str.find(f) != std::string::npos)
                {
                    strings.push_back(str);
                }
                if (strings.size() > 500)
                    break;
            }
        };

        struct SyncData
        {
            char *filter;
            bool *externalChanged;
        };
        static SyncData data = {filter, &externalChanged};

        if (ImGui::InputText("Search Text", filter, sizeof(filter), ImGuiInputTextFlags_CallbackAlways,
                            [](ImGuiInputTextCallbackData *data)
                            {
                                SyncData *s = (SyncData *)data->UserData;
                                if (*s->externalChanged)
                                {
                                    data->DeleteChars(0, data->BufTextLen);
                                    data->InsertChars(0, s->filter);
                                    *s->externalChanged = false;
                                }
                                return 0;
                            },
                            &data))
        {
            searchStrings(filter);
        }

        if (ImGui::IsItemClicked())
        {
            Keyboard::Open(filter,
                           [searchStrings](const std::string &text)
                           {
                               strncpy(filter, text.c_str(), sizeof(filter));
                               externalChanged = true;
                               searchStrings(filter);
                           });
        }
        if (ImGui::Button("Refresh", ImVec2(MenuLayout::IsNarrowLayout() ? -1.f : 0.f, 0.f)))
        {
            searchStrings(filter);
        }

        ImGui::Separator();
        ImGui::Text("Found: %zu", strings.size());

        ImGui::BeginChild("StringList", ImVec2(0, MenuLayout::ScrollPanelHeight(0.65f, 160.f)),
                          ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
        for (int i = 0; i < strings.size(); i++)
        {
            ImGui::Text("[%d]: %s", i, strings[i].c_str());
            if (ImGui::IsItemClicked())
            {
                ImGui::SetClipboardText(strings[i].c_str());
                AddNotification("Success", "Copied to clipboard!", true);
            }
        }
        ImGui::EndChild();
    }

    bool isCapturing = false;
    int captureImageIdx = 0;
    bool captureAll = false;
    int maxFunctions = 5000;
    std::vector<MethodInfo *> sessionMethods;

    void Dumper()
    {
        static bool isDumping = false;
        static float dumpProgress = 0.0f;
        static char dumpStatus[256] = "Ready";
        static char currentAssembly[128] = "";

        if (dumpPaths.empty())
            InitDumpPaths();

        ImGui::Spacing();

        if (!Il2cpp::IsDumperReady())
        {
            ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Il2Cpp not ready!");
            return;
        }

        // Path Selection
        const char *currentPath = dumpPaths[selectedPathIdx].c_str();
        if (ImGui::BeginCombo("##DumpLocation", currentPath))
        {
            for (int i = 0; i < dumpPaths.size(); i++)
            {
                bool isSelected = (selectedPathIdx == i);
                if (ImGui::Selectable(dumpPaths[i].c_str(), isSelected))
                {
                    selectedPathIdx = i;
                }
                if (isSelected)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        ImGui::Text("Dump Location");

        ImGui::Spacing();

        if (isDumping)
        {
            ImGui::Button("Dumping...", ImVec2(-1, 0));
            ImGui::ProgressBar(dumpProgress, ImVec2(-1.0f, 0.0f));
            ImGui::Text("Status: %s", dumpStatus);
            ImGui::Text("Assembly: %s", currentAssembly);
        }
        else
        {
            if (ImGui::Button("Dump", ImVec2(-1, 0)))
            {
                isDumping = true;
                dumpProgress = 0.0f;
                strcpy(dumpStatus, "Starting...");

                std::string pkg = Il2cpp::getPackageName();
                std::string archSuffix = (sizeof(void *) == 8) ? "_64bit" : "_32bit";
                std::string outputPath = dumpPaths[selectedPathIdx] + "/" + pkg + archSuffix + ".cs";

                std::thread([outputPath]() {
                    bool success = Il2cpp::Dump(outputPath, [](const Il2cpp::DumpProgress &progress) {
                        dumpProgress = progress.progress;
                        snprintf(dumpStatus, sizeof(dumpStatus), "Processing: %d/%d classes", progress.currentClassIndex,
                                 progress.totalClasses);
                        strncpy(currentAssembly, progress.currentAssembly.c_str(), sizeof(currentAssembly) - 1);
                    });

                    isDumping = false;
                    if (success)
                    {
                        AddNotification("Success", "Dump success!", true);
                    }
                    else
                    {
                        AddNotification("Failed", "Dump failed!", false);
                    }
                }).detach();
            }
        }

        ImGui::Spacing();
        ImGui::SeparatorText("Runtime API Dumper");

        ImGui::BeginDisabled(captureAll || isCapturing);
        if (ImGui::BeginCombo("Image##CaptureImage", g_Images.empty() ? "None" : g_Images[captureImageIdx]->getName()))
        {
            for (int i = 0; i < g_Images.size(); i++)
            {
                bool isSelected = (captureImageIdx == i);
                if (ImGui::Selectable(g_Images[i]->getName(), isSelected))
                {
                    captureImageIdx = i;
                }
                if (isSelected)
                    ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::BeginDisabled(isCapturing);
        ImGui::Checkbox("All", &captureAll);
        ImGui::EndDisabled();

        ImGui::BeginDisabled(isCapturing);
        static char maxFuncBuf[16] = "";
        static bool externalChanged = false;
        static bool bufInit = false;
        if (!bufInit) {
            snprintf(maxFuncBuf, sizeof(maxFuncBuf), "%d", maxFunctions);
            bufInit = true;
        }

        struct SyncData { char *buf; bool *changed; int *val; };
        SyncData sData = { maxFuncBuf, &externalChanged, &maxFunctions };

        if (ImGui::InputText("Max Functions", maxFuncBuf, sizeof(maxFuncBuf),
                            ImGuiInputTextFlags_CharsDecimal | ImGuiInputTextFlags_CallbackAlways,
                            [](ImGuiInputTextCallbackData *data) {
                                SyncData *s = (SyncData *)data->UserData;
                                if (*s->changed) {
                                    data->DeleteChars(0, data->BufTextLen);
                                    data->InsertChars(0, s->buf);
                                    *s->changed = false;
                                }
                                return 0;
                            }, &sData))
        {
            try {
                maxFunctions = std::stoi(maxFuncBuf);
                if (maxFunctions < 1) maxFunctions = 1;
            } catch (...) {}
        }
        if (ImGui::IsItemClicked())
        {
            Keyboard::Open(maxFuncBuf,
                           [](const std::string &text)
                           {
                               try
                               {
                                   if (!text.empty())
                                   {
                                       maxFunctions = std::stoi(text);
                                       if (maxFunctions < 1)
                                           maxFunctions = 1;
                                       snprintf(maxFuncBuf, sizeof(maxFuncBuf), "%d", maxFunctions);
                                       externalChanged = true;
                                   }
                               }
                               catch (...)
                               {
                               }
                           });
        }
        ImGui::EndDisabled();

        if (!isCapturing)
        {
            static bool isStarting = false;
            ImGui::BeginDisabled(isStarting);
            if (ImGui::Button(isStarting ? "Starting..." : "Start Capture", ImVec2(ImGui::GetContentRegionAvail().x / 2.0f, 0)))
            {
                isStarting = true;
                {
                    std::lock_guard guard(hookerMtx);
                    sessionMethods.clear();
                }

                std::thread([captureAllLocal = captureAll, captureImageIdxLocal = captureImageIdx, maxFunctionsLocal = maxFunctions]() {
                    int count = 0;
                    std::vector<MethodInfo*> localSessionMethods;

                    auto hookClasses = [&](const std::vector<Il2CppClass *> &classes)
                    {
                        for (auto klass : classes)
                        {
                            if (Il2cpp::GetClassIsEnum(klass))
                                continue;
                            for (auto method : klass->getMethods())
                            {
                                if (method->methodPointer && count < maxFunctionsLocal)
                                {
                                    if (ToggleHooker(method, 1, true))
                                    {
                                        localSessionMethods.push_back(method);
                                        count++;
                                    }
                                }
                                if (count >= maxFunctionsLocal)
                                    return;
                            }
                        }
                    };

                    if (captureAllLocal)
                    {
                        for (auto img : g_Images)
                        {
                            hookClasses(img->getClasses());
                            if (count >= maxFunctionsLocal)
                                break;
                        }
                    }
                    else if (!g_Images.empty())
                    {
                        hookClasses(g_Images[captureImageIdxLocal]->getClasses());
                    }

                    {
                        std::lock_guard guard(hookerMtx);
                        sessionMethods = std::move(localSessionMethods);
                        isCapturing = count > 0;
                    }

                    isStarting = false;
                    if (count > 0)
                    {
                        AddNotification("Success", "Capture started! Hooked " + std::to_string(count) + " methods.", true);
                    }
                    else
                    {
                        AddNotification("Warning", "No methods found to hook.", false);
                    }
                }).detach();
            }
            ImGui::EndDisabled();
        }
        else
        {
            int calledCount = 0;
            {
                std::lock_guard guard(hookerMtx);
                for (auto method : sessionMethods)
                {
                    auto it = hookerMap.find(method->methodPointer);
                    if (it != hookerMap.end() && it->second.hitCount > 0)
                        calledCount++;
                }
            }
            ImGui::Text("Methods Hooked: %zu", sessionMethods.size());
            ImGui::Text("Methods Called: %d", calledCount);

            if (ImGui::Button("Stop Capture", ImVec2(ImGui::GetContentRegionAvail().x / 2.0f, 0)))
            {
                std::string pkg = Il2cpp::getPackageName();
                std::string outputPath = dumpPaths[selectedPathIdx] + "/runtime_dump.c";

                auto methodsToUnhook = sessionMethods;
                sessionMethods.clear();
                isCapturing = false;

                std::thread([outputPath, methodsToUnhook]()
                {
                    std::ofstream file(outputPath);
                    int dumpedCount = 0;
                    if (file.is_open())
                    {
                        std::lock_guard guard(hookerMtx);
                        for (auto method : methodsToUnhook)
                        {
                            auto it = hookerMap.find(method->methodPointer);
                            if (it != hookerMap.end() && it->second.hitCount > 0)
                            {
                                char line[2048];
                                auto klass = method->getClass();
                                std::string signature = Il2cpp::GetMethodSignature(method);

                                snprintf(line, sizeof(line), "\n//0x%llx\n%s::%s { } //captured %d times",
                                         (unsigned long long)method->getAbsAddress(),
                                         klass->getName(), signature.c_str(), (int)it->second.hitCount);
                                file << line << "\n";
                                dumpedCount++;
                            }
                        }
                        file.close();
                    }
                    else
                    {
                        LOGE("Failed to open %s for writing", outputPath.c_str());
                    }

                    for (auto method : methodsToUnhook)
                    {
                        ToggleHooker(method, 0);
                    }

                    if (dumpedCount > 0)
                        AddNotification("Success", "Dumped " + std::to_string(dumpedCount) + " methods to " + outputPath,
                                        true);
                    else
                        AddNotification("Warning", "No methods were called during capture.", false);
                }).detach();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Clear", ImVec2(-1, 0)))
        {
            std::lock_guard guard(hookerMtx);
            if (isCapturing)
            {
                for (auto method : sessionMethods)
                {
                    auto it = hookerMap.find(method->methodPointer);
                    if (it != hookerMap.end())
                        it->second.hitCount = 0;
                }
            }
            else
            {
                for (auto &pair : hookerMap)
                    pair.second.hitCount = 0;
            }
            HookerData::visited.clear();
            AddNotification("Success", "Hit counts and traces cleared.", true);
        }
    }

    struct Vec3
    {
        float x, y, z;
    };

    void GameObjects()
    {
        static std::vector<Il2CppObject *> GameObjects = []()
        {
            auto GO = Il2cpp::FindClass("UnityEngine.GameObject");
            return Il2cpp::GC::FindObjects(GO);
        }();
        static std::vector<Il2CppObject *> Transforms = []()
        {
            auto t = Il2cpp::FindClass("UnityEngine.Transform");
            return Il2cpp::GC::FindObjects(t);
        }();
        static Il2CppObject *cam = []()
        {
            auto Camera = Il2cpp::FindClass("UnityEngine.Camera");
            auto cam = Camera->invoke_static_method<Il2CppObject *>("get_current");
            LOGPTR(cam);
            return cam;
        }();
        static MethodInfo *WorldToScreenPoint = []()
        {
            // public UnityEngine.Vector3 WorldToScreenPoint(UnityEngine.Vector3 position); // 0x28c04bc
            auto M = cam->klass->getMethods("WorldToScreenPoint")[1];
            LOGPTR(M);
            LOGPTR(M->methodPointer);
            return M;
        }();

        static MethodInfo *IsNativeObjectAlive = []()
        {
            // private static System.Boolean IsNativeObjectAlive(UnityEngine.Object o); // 0x28c8058
            auto UnityObject = Il2cpp::FindClass("UnityEngine.Object");
            return UnityObject->getMethod("IsNativeObjectAlive");
        }();

        ImGui::Text("GameObjects %zu", GameObjects.size());
        // if (ImGui::Button("CC"))
        // {
        // std::vector<Vec3> vecs;
        // for (auto go : GameObjects)
        // {
        //     auto transform = go->invoke_method<Il2CppObject *>("get_transform");
        //     auto position = transform->invoke_method<ValueType<Vec3>>("get_position");
        //     // auto screen = WorldToScreenPoint->invoke_static<Vec3>(cam, position);
        //     auto arrParam = new Il2CppObject *[1];
        //     arrParam[0] = position.box(Il2cpp::FindClass("UnityEngine.Vector3"));
        //     auto screenObj = Il2cpp::RuntimeInvokeConvertArgs(WorldToScreenPoint, cam, arrParam, 1);
        //     delete[] arrParam;
        //     auto screen = Il2cpp::GetUnboxedValue<Vec3>(screenObj);
        //     vecs.push_back(screen);
        //     // LOGD("%.2f %.2f %.2f | %.2f %.2f %.2f", position.value.x, position.value.y, position.value.z,
        //     // screen.x,
        //     //      screen.y, screen.z);
        // }
        // LOGD("%d", vecs.size());
        auto drawList = ImGui::GetForegroundDrawList();
        static auto center = ImVec2(ImGui::GetIO().DisplaySize.x / 2, ImGui::GetIO().DisplaySize.y / 2);
        for (auto go : GameObjects)
        {
            static bool (*IsAlive)(void *) = (decltype(IsAlive))IsNativeObjectAlive->methodPointer;
            // if (!IsAlive(go))
            // {
            //     continue;
            // }
            if (IsNativeObjectAlive->invoke_static<bool>(go) == false)
            {
                continue;
            }
            auto transform = go->invoke_method<Il2CppObject *>("get_transform");
            auto position = transform->invoke_method<Vec3>("get_position");
            // LOGD("%.2f %.2f %.2f", position.x, position.y, position.z);
            auto screen = WorldToScreenPoint->invoke_static<Vec3>(cam, position);
            // static Vec3 (*WTS)(void *, Vec3) = (decltype(WTS))WorldToScreenPoint->methodPointer;
            // auto screen = WTS(cam, position);
            ImVec2 pos = ImVec2(screen.x, screen.y);
            drawList->AddLine(center, pos, IM_COL32(255, 50, 50, 255));

            // LOGD("%.2f %.2f %.2f | %.2f %.2f %.2f", position.x, position.y, position.z, screen.x, screen.y,
            //      screen.z);
        }
        // }
    }

    //-1 = Auto
    // 0 = Off
    // 1 = On
    bool ToggleHooker(MethodInfo *method, int state, bool silent)
    {
        {
            std::lock_guard guard(ClassesTab::oMapMtx);
            // Save original bytes if not already saved, so Assembly/Hex view can highlight changes
            auto &o = ClassesTab::oMap[method];
            if (o.bytes.empty() && method->methodPointer)
            {
                // Save first 16 bytes (typical max for a hook)
                o.bytes.assign((uint8_t *)method->methodPointer, (uint8_t *)method->methodPointer + 16);
                // We don't set o.text because it's not a return-value patch
            }
        }

        static auto printHex = [](void *ptr, int row = 1)
        {
            if (row < 1)
            {
                row = 1;
            }
            for (int i = 0; i < row; i++)
            {
                char buffer[512]{0};
                uint8_t *bytes = (uint8_t *)ptr + i * 16;
                for (int j = 0; j < 16; j++)
                {
                    sprintf(buffer + j * 3, "%02X ", bytes[j]);
                }
                LOGD("%s", buffer);
            }
        };
        auto it = hookerMap.find(method->methodPointer);
        bool hooked = it != hookerMap.end();
#ifndef USE_FRIDA
        auto EnableHookerDobby = [&method, silent]
        {
            LOGD("%s", method->getName());
            printHex(method->methodPointer);
            std::span<uint8_t> originalBytes((uint8_t *)method->methodPointer, (uint8_t *)method->methodPointer + 8);
    #ifdef __aarch64__
            constexpr std::array<uint8_t, 4> ret = {0xC0, 0x03, 0x5F, 0xD6};
            auto it = std::search(originalBytes.begin(), originalBytes.end(), ret.begin(), ret.end());
    #else
            constexpr std::array<uint8_t, 4> bxLr = {0x1E, 0xFF, 0x2F, 0xE1};
            auto it = std::search(originalBytes.begin(), originalBytes.end(), bxLr.begin(), bxLr.end());
    #endif
            auto shortFunction = it != originalBytes.end();
            if (shortFunction)
            {
                dobby_enable_near_branch_trampoline();
            }
            // 1E FF 2F E1 = bx lr
            if (DobbyInstrument((void *)method->methodPointer, hookerHandler) == 0)
            {
                printHex(method->methodPointer);
                std::lock_guard guard(hookerMtx);
                hookerMap[method->methodPointer].hitCount = 0;
                hookerMap[method->methodPointer].method = method;
                hookerMap[method->methodPointer].silent = silent;
                if (shortFunction)
                {
                    dobby_disable_near_branch_trampoline();
                }
                return true;
            }
            else
            {
                LOGE("Failed to instrument %s", method->getName());
                if (shortFunction)
                {
                    dobby_disable_near_branch_trampoline();
                }
                return false;
            }
        };

        auto DisableHookerDobby = [&method]
        {
            if (DobbyDestroy(method->methodPointer) == 0)
            {
                std::lock_guard guard(hookerMtx);
                hookerMap.erase(method->methodPointer);
                return true;
            }
            else
            {
                LOGE("Failed to restore %s", method->getName());
                // Force erase anyway to keep UI clean
                std::lock_guard guard(hookerMtx);
                hookerMap.erase(method->methodPointer);
                return false;
            }
        };
        auto EnableHooker = EnableHookerDobby;
        auto DisableHooker = DisableHookerDobby;
#else
        auto EnableHookerFrida = [&method, silent]()
        {
            bool result = true;
            LOGD("%s", method->getName());
            printHex(method->methodPointer);
            uint8_t *begin = (uint8_t *)method->methodPointer;
            uint8_t *end = begin + 8;
    #ifdef __aarch64__
            constexpr std::array<uint8_t, 4> ret = {0xC0, 0x03, 0x5F, 0xD6};
            auto it = std::search(begin, end, ret.begin(), ret.end());
    #else
            constexpr std::array<uint8_t, 4> bxLr = {0x1E, 0xFF, 0x2F, 0xE1};
            auto it = std::search(begin, end, bxLr.begin(), bxLr.end());
    #endif
            bool shortFunction = (it != end);
            if (shortFunction)
            {
                LOGD("Short function");
            }
            std::lock_guard guard(hookerMtx);
            hookerMap[method->methodPointer].hitCount = 0;
            hookerMap[method->methodPointer].method = method;
            hookerMap[method->methodPointer].silent = silent;
            if (!Frida::Trace(method, &hookerMap[method->methodPointer]))
            {
                hookerMap.erase(method->methodPointer);
                LOGE("Failed to instrument %s", method->getName());
                result = false;
            }
            printHex(method->methodPointer);
            return result;
        };

        auto DisableHookerFrida = [&method]
        {
            if (Frida::Untrace(method))
            {
                std::lock_guard guard(hookerMtx);
                hookerMap.erase(method->methodPointer);
                return true;
            }
            LOGE("Failed to restore %s", method->getName());
            // Force erase anyway to keep UI clean
            std::lock_guard guard(hookerMtx);
            hookerMap.erase(method->methodPointer);
            return false;
        };
        auto EnableHooker = EnableHookerFrida;
        auto DisableHooker = DisableHookerFrida;
#endif

        if (state == -1)
        {
            if (!hooked)
            {
                return EnableHooker();
            }
            else
            {
                return DisableHooker();
            }
        }
        else if (state == 0)
        {
            if (hooked)
            {
                return DisableHooker();
            }
            return true;
        }
        else if (state == 1)
        {
            if (!hooked)
            {
                return EnableHooker();
            }
            else
            {
                std::lock_guard guard(hookerMtx);
                hookerMap[method->methodPointer].silent = silent;
                return true;
            }
        }
        return false;
    }
} // namespace Tool
