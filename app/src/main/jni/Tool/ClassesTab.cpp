#include "ClassesTab.h"
#include <algorithm>
#include "Il2cpp/Il2cpp.h"
#include "Tool/Keyboard.h"
#include "Tool/Patcher.h"
#include "Tool/Tool.h"
#include "Tool/Util.h"
#include "Includes/Utils.h"
#include "imgui/imgui.h"
#include <mutex>
#include <thread>
#include <unordered_map>
#include "sstream"
#include <vector>

#include <frida-gum.h>
#include <inttypes.h>

extern "C" {
    cs_err _frida_cs_open(cs_arch arch, cs_mode mode, csh *handle);
    size_t _frida_cs_disasm(csh handle, const uint8_t *code, size_t code_size, uint64_t address, size_t count, cs_insn **insn);
    void _frida_cs_free(cs_insn *insn, size_t count);
    cs_err _frida_cs_close(csh *handle);
}

#define cs_open _frida_cs_open
#define cs_disasm _frida_cs_disasm
#define cs_free _frida_cs_free
#define cs_close _frida_cs_close

extern std::vector<Il2CppImage *> g_Images;
extern Il2CppImage *g_Image;

constexpr int MAX_CLASSES = 500;

int maxLine{5};
std::unordered_map<void *, HookerData> hookerMap;
std::mutex hookerMtx;

#ifndef USE_FRIDA
void hookerHandler(void *address, DobbyRegisterContext *ctx)
{
    hookerMtx.lock();
    auto it = hookerMap.find(address);
    if (it == hookerMap.end())
    {
        hookerMtx.unlock();
        return;
    }
    auto &hookerData = it->second;
    hookerData.hitCount++;

    if (hookerData.silent)
    {
        hookerMtx.unlock();
        return;
    }

    hookerData.time = 1.f;
    auto name = hookerData.method->getName();
    auto absAddress = hookerData.method->getAbsAddress();
    hookerMtx.unlock();

    char buffer[128]{0};
    sprintf(buffer, "%p | %s", (void*)absAddress, name);

    int i = 0;
    for (auto it_visited = HookerData::visited.rbegin(); it_visited != HookerData::visited.rend(); ++it_visited)
    {
        if (i >= maxLine)
        {
            break;
        }
        if (it_visited->name == buffer)
        {
            it_visited->goneTime = 10.f;
            it_visited->time = 2.f;
            it_visited->hitCount++;
            return;
        }
        i++;
    }
    HookerData::visited.push_back({buffer, 2.f, 10.f, 0});
}
#endif

ClassesTab::MethodList &ClassesTab::buildMethodMap(Il2CppClass *klass)
{
    static Il2CppClass *lastClass = nullptr;
    static MethodList methodList;

    if (lastClass != klass)
    {
        methodList.clear();
        auto methods = klass->getMethods();
        LOGD("Rebuilding %s | %lu methods", klass->getName(), methods.size());
        for (auto method : methods)
        {
            auto paramsInfo = method->getParamsInfo();
            methodList.push_back({method, paramsInfo});
        }
        LOGD("Rebuilt %lu methods", methodList.size());
        lastClass = klass;
    }
    return methodList;
}

ClassesTab::ClassesTab()
{
    selectedImage = g_Image;

    for (int i = 0; i < g_Images.size(); i++)
    {
        if (g_Images[i] == selectedImage)
        {
            selectedImageIndex = i;
            break;
        }
    }
    classes = selectedImage->getClasses();
    filteredClasses = classes;
}

ClassesTab::Paths &ClassesTab::getJsonPaths(Il2CppObject *object)
{
    return dataMap[object].second;
}

void ClassesTab::setJsonObject(Il2CppObject *object)
{
    // std::vector<uintptr_t> visited{};
    // dataMap[object].first = object->dump(visited, 9999);
    dataMap[object].first = object->dump({});

    tabMap.emplace(object, true);
}

ClassesTab::Json &ClassesTab::getJsonObject(Il2CppObject *object)
{
    return dataMap[object].first.second;
}

void ClassesTab::ImGuiObjectSelector(int id, Il2CppClass *klass, const char *prefix,
                                     std::function<void(Il2CppObject *)> onSelect, bool canNew)
{
    ImGui::PushID(id);
    static std::unordered_map<void *, bool> scanState;
    auto &scanning = scanState[klass];
    if (ImGui::Button("Find Objects"))
    {
        scanning = true;
        std::thread(
            [&scanning](Il2CppClass *klass)
            {
                objectMap[klass] = Il2cpp::GC::FindObjects(klass);
                scanning = false;
            },
            klass)
            .detach();
    }
    ImGui::PopID();
    ImGuiIO &io = ImGui::GetIO();
    float width = io.DisplaySize.x;
    float height = io.DisplaySize.y;
    // FIXME: DRY!!
    {
        auto &objects = objectMap[klass];
        ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
        ImGui::BeginChild("##ScrollingObjects", ImVec2(width / 1.4f, 0), ImGuiChildFlags_AutoResizeY);
        {
            ImGui::SeparatorText("Result Object");
            if (objects.empty())
            {
                if (scanning)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(50, 255, 50, 255));
                }
                else
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                }
                if (scanning)
                {
                    ImGui::Text("Scanning...");
                }
                else
                {
                    ImGui::Text("Nothing...");
                }
                ImGui::PopStyleColor();
            }
            else
            {
                if (objects.size() > 100)
                {
                    ImGui::Text("Showing 100 of %zu objects", objects.size());
                }
                for (auto it = objects.begin(); it != (objects.size() > 100 ? objects.begin() + 100 : objects.end());)
                {
                    auto object = *it;
                    char buff[64];
                    sprintf(buff, "%s [%p]", prefix, object);
                    auto size = ImGui::GetWindowSize();
                    if (ImGui::Button(buff, ImVec2(size.x / 1.5, 0)))
                    {
                        onSelect(object);
                    }
                    ImGui::SetItemTooltip("%s", object->klass->getName());
                    ImGui::SameLine();
                    ImGui::PushID(buff);
                    if (ImGui::Button("Remove"))
                    {
                        it = objects.erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                    ImGui::PopID();
                }
            }
        }
        ImGui::EndChild();
    }
    ImGui::Separator();

    // ImGui::Text("Inherited from %s", klass->getName());
    // for (auto [setKlass, _] : savedSet)
    // {
    //     if (klass != setKlass && Il2cpp::IsClassParentOf(setKlass, klass))
    //     {
    //         ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
    //         ImGui::BeginChild("##ScrollingInheritObjects", ImVec2(width / 2.f, 0), ImGuiChildFlags_AutoResizeY);
    //         for (auto object : savedSet[setKlass])
    //         {
    //             char buff[64];
    //             sprintf(buff, "%s [%p]", setKlass->getName(), object);
    //             if (ImGui::Button(buff))
    //             {
    //                 onSelect(object);
    //             }
    //         }
    //         ImGui::EndChild();
    //     }
    // }
    // ImGui::Separator();

    {
        char buffer[128];
        sprintf(buffer, "Inherited from %s", klass->getName());
        if (ImGui::CollapsingHeader(buffer))
        {
            ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
            ImGui::BeginChild("##ScrollingInheritedObjects", ImVec2(width / 1.4f, 0), ImGuiChildFlags_AutoResizeY);
            {
                // {
                //     char buffer[128];
                //     sprintf(buffer, "Inherited from %s", klass->getName());
                //     ImGui::SeparatorText(buffer);
                // }
                bool empty = true;
                for (auto &[setKlass, _] : savedSet)
                {
                    if (klass != setKlass && Il2cpp::IsClassParentOf(setKlass, klass))
                    {
                        auto &objects = savedSet[setKlass];
                        for (auto it = objects.begin(); it != objects.end();)
                        {
                            empty = false;
                            auto object = *it;
                            char buff[64];
                            sprintf(buff, "%s [%p]", setKlass->getName(), object);
                            auto size = ImGui::GetWindowSize();
                            if (ImGui::Button(buff, ImVec2(size.x / 1.5, 0)))
                            {
                                onSelect(object);
                            }
                            ImGui::SetItemTooltip("%s", object->klass->getName());
                            ImGui::SameLine();
                            ImGui::PushID(buff);
                            if (ImGui::Button("Remove"))
                            {
                                it = objects.erase(it);
                            }
                            else
                            {
                                ++it;
                            }
                            ImGui::PopID();
                        }
                    }
                }

                if (empty)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                    ImGui::Text("Nothing...");
                    ImGui::PopStyleColor();
                }
            }
            ImGui::EndChild();
        }
    }
    // ImGui::Text("Saved objects");
    // if (savedSet[klass].empty())
    // {
    //     ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
    //     ImGui::Text("No objects");
    //     ImGui::PopStyleColor();
    // }
    // else
    // {
    //     ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
    //     ImGui::BeginChild("##ScrollingSavedObjects", ImVec2(width / 2.f, 0), ImGuiChildFlags_AutoResizeY);
    //     for (auto object : savedSet[klass])
    //     {
    //         char buff[64];
    //         sprintf(buff, "%s [%p]", klass->getName(), object);
    //         if (ImGui::Button(buff))
    //         {
    //             onSelect(object);
    //         }
    //     }
    //     ImGui::EndChild();
    // }
    // ImGui::Separator();

    {
        if (ImGui::CollapsingHeader("Saved Objects"))
        {
            auto &objects = savedSet[klass];
            ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
            ImGui::BeginChild("##ScrollingSavedObjects", ImVec2(width / 1.4f, 0), ImGuiChildFlags_AutoResizeY);
            {
                // ImGui::SeparatorText("Saved Objects");
                if (objects.empty())
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                    ImGui::Text("Nothing...");
                    ImGui::PopStyleColor();
                }
                else
                {
                    for (auto it = objects.begin(); it != objects.end();)
                    {
                        auto object = *it;
                        char buff[64];
                        sprintf(buff, "%s [%p]", klass->getName(), object);
                        auto size = ImGui::GetWindowSize();
                        if (ImGui::Button(buff, ImVec2(size.x / 1.5, 0)))
                        {
                            onSelect(object);
                        }
                        ImGui::SetItemTooltip("%s", object->klass->getName());
                        ImGui::SameLine();
                        ImGui::PushID(buff);
                        if (ImGui::Button("Remove"))
                        {
                            it = objects.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                        ImGui::PopID();
                    }
                }
            }
            ImGui::EndChild();
        }
    }
    // ImGui::Text("Collected objects");
    // if (HookerData::collectSet.find(klass) == HookerData::collectSet.end())
    // {
    //     ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
    //     ImGui::Text("No objects");
    //     ImGui::PopStyleColor();
    // }
    // else
    // {
    //     ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
    //     ImGui::BeginChild("##ScrollingCollectedObjects", ImVec2(width / 2.f, 0), ImGuiChildFlags_AutoResizeY);
    //     for (auto object : HookerData::collectSet[klass])
    //     {
    //         char buff[64];
    //         sprintf(buff, "%s [%p]", klass->getName(), object);
    //         if (ImGui::Button(buff))
    //         {
    //             onSelect(object);
    //         }
    //     }
    //     ImGui::EndChild();
    // }
    // ImGui::Separator();

    {
        if (ImGui::CollapsingHeader("Collected Objects"))
        {
            auto &objects = HookerData::collectSet[klass];
            ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
            ImGui::BeginChild("##ScrollingCollectedObjects", ImVec2(width / 1.4f, 0), ImGuiChildFlags_AutoResizeY);
            {
                // ImGui::SeparatorText("Collected Objects");
                if (objects.empty())
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                    ImGui::Text("Nothing...");
                    ImGui::PopStyleColor();
                }
                else
                {
                    for (auto it = objects.begin(); it != objects.end();)
                    {
                        auto object = *it;
                        char buff[64];
                        sprintf(buff, "%s [%p]", klass->getName(), object);
                        auto size = ImGui::GetWindowSize();
                        if (ImGui::Button(buff, ImVec2(size.x / 1.5, 0)))
                        {
                            onSelect(object);
                        }
                        ImGui::SetItemTooltip("%s", object->klass->getName());
                        ImGui::SameLine();
                        ImGui::PushID(buff);
                        if (ImGui::Button("Remove"))
                        {
                            it = objects.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                        ImGui::PopID();
                    }
                }
            }
            ImGui::EndChild();
        }
    }
    // if (canNew)
    // {
    //     if (ImGui::Button("New"))
    //     {
    //         auto newObject = klass->New();
    //         newObjectMap[klass].push_back(newObject);
    //         if (Il2cpp::GetClassType(klass)->isValueType())
    //         {
    //             newObject = (Il2CppObject *)Il2cpp::GetUnboxedValue(newObject);
    //         }
    //         onSelect(newObject);
    //     }
    // }
    // else
    // {
    //     ImGui::Text("Created objects");
    // }

    // ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
    // ImGui::BeginChild("##ScrollingNewObjects", ImVec2(width / 2.f, 0), ImGuiChildFlags_AutoResizeY);
    // for (auto createObject : newObjectMap[klass])
    // {
    //     char buff[64];
    //     sprintf(buff, "%s [%p]", prefix, createObject);
    //     if (ImGui::Button(buff))
    //     {
    //         onSelect(createObject);
    //     }
    // }
    // ImGui::EndChild();

    {
        if (ImGui::CollapsingHeader("Created Objects"))
        {
            auto &objects = newObjectMap[klass];
            ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0), ImVec2(-1, height / 3));
            ImGui::BeginChild("##ScrollingNewObjects", ImVec2(width / 1.4f, 0), ImGuiChildFlags_AutoResizeY);
            {
                // ImGui::SeparatorText("Created Objects");
                if (objects.empty())
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
                    ImGui::Text("Nothing...");
                    ImGui::PopStyleColor();
                }
                else
                {
                    for (auto it = objects.begin(); it != objects.end();)
                    {
                        auto object = *it;
                        char buff[64];
                        sprintf(buff, "%s [%p]", prefix, object);
                        auto size = ImGui::GetWindowSize();
                        if (ImGui::Button(buff, ImVec2(size.x / 1.5, 0)))
                        {
                            onSelect(object);
                        }
                        ImGui::SetItemTooltip("%s", object->klass->getName());
                        ImGui::SameLine();
                        ImGui::PushID(buff);
                        if (ImGui::Button("Remove"))
                        {
                            it = objects.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                        ImGui::PopID();
                    }
                }
                if (canNew)
                {
                    if (ImGui::Button("New"))
                    {
                        auto newObject = klass->New();
                        newObjectMap[klass].push_back(newObject);
                        if (Il2cpp::GetClassType(klass)->isValueType())
                        {
                            // Il2cpp::GC::KeepAlive(newObject);
                            newObject = (Il2CppObject *)Il2cpp::GetUnboxedValue(newObject);
                        }
                        onSelect(newObject);
                    }
                }
            }
            ImGui::EndChild();
        }
    }
    // if (!objectMap.empty())
    // {
    //     ImGui::Separator();
    //     static Il2CppObject *selected = nullptr;
    //     if (ImGui::Button("Force Select Existing"))
    //     {
    //         ImGui::OpenPopup("ForceObjectSelector");
    //         selected = nullptr;
    //     }
    //     if (ImGui::BeginPopup("ForceObjectSelector"))
    //     {
    //         for (auto it = objectMap.begin(); it != objectMap.end() && selected == nullptr; it++)
    //         {
    //             auto [objKlass, objects] = *it;
    //             char klassName[256]{0};
    //             for (auto object : objects)
    //             {
    //                 sprintf(klassName, "%s [%p]", objKlass->getName(), object);
    //                 if (ImGui::Button(klassName))
    //                 {
    //                     selected = object;
    //                     break;
    //                 }
    //             }
    //         }
    //         ImGui::EndPopup();
    //     }
    //     if (selected)
    //     {
    //         onSelect(selected);
    //         selected = nullptr;
    //     }
    // }
}

void ClassesTab::CallerView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                            Il2CppObject *thiz)
{
    static ImGuiIO &io = ImGui::GetIO();
    bool methodIsStatic = Il2cpp::GetIsMethodStatic(method);
    auto &params = paramMap[method];
    if (!methodIsStatic && !thiz)
    {
        auto &thisParam = params["this"];
        char thisLabel[128]{0};
        sprintf(thisLabel, "%s this", Il2cpp::GetClassType(klass)->getName());
        if (!thisParam.value.empty())
        {
            sprintf(thisLabel, "%s = %s", thisLabel, thisParam.value.c_str());
        }
        if (ImGui::Button(thisLabel))
        {
            ImGui::OpenPopup("ThisObjectSelector");
        }
        if (ImGui::BeginPopup("ThisObjectSelector"))
        {
            ImGuiObjectSelector(
                ImGui::GetID("ThisObjectSelector"), klass, "this",
                [&thisParam](Il2CppObject *object)
                {
                    char objStr[16]{0};
                    sprintf(objStr, "%p", object);
                    thisParam.value = objStr;
                    thisParam.object = object;
                    ImGui::CloseCurrentPopup();
                },
                strcmp(method->getName(), ".ctor") == 0);
            ImGui::EndPopup();
        }
    }
    for (int k = 0; k < paramsInfo.size(); k++)
    {
        auto &[name, type] = paramsInfo[k];

        char paramKey[64]{0};
        sprintf(paramKey, "%p%s%d", method, name, k);
        auto &param = params[paramKey];

        char buttonLabel[128]{0};
        sprintf(buttonLabel, "%s %s", type->getName(), name);
        if (!param.value.empty())
        {
            sprintf(buttonLabel, "%s = %s", buttonLabel, param.value.c_str());
        }
        ImGui::PushID(k);
        if (ImGui::Button(buttonLabel))
        {
            bool isString = strcmp(type->getName(), "System.String") == 0;
            if (type->isPrimitive() || isString)
            {
                if (strcmp(type->getName(), "System.Boolean") == 0)
                {
                    // ImGui::OpenPopup("BooleanSelector");
                    poper.Open("BooleanSelector", [&param](const std::string &result) { param.value = result; });
                }
                else
                {
                    Keyboard::Open(
                        [&param, &isString](const std::string &text)
                        {
                            if (isString)
                            {
                                param.object = Il2cpp::NewString(text.c_str());
                            }
                            param.value = text;
                        });
                }
            }
            else if (type->isEnum())
            {
                poper.Open(
                    "EnumSelector", [&param](const std::string &result) { param.value = result; }, type);
            }
            // else if (!type->isValueType() && !(type->isArray() || type->isList()
            // ||
            //                                    strstr(type->getName(),
            //                                    "System.Object")))
            // else if (!strstr(type->getName(), "System.Object"))
            else
            {
                ImGui::OpenPopup("ParamObjectSelector");
            }
        }
        if (ImGui::BeginPopup("ParamObjectSelector"))
        {
            ImGuiObjectSelector(ImGui::GetID("ParamObjectSelector"), type->getClass(), name,
                                [&param](Il2CppObject *object)
                                {
                                    char objStr[16]{0};
                                    sprintf(objStr, "%p", object);
                                    param.value = objStr;
                                    param.object = object;
                                    ImGui::CloseCurrentPopup();
                                });
            ImGui::EndPopup();
        }
        ImGui::PopID();
    }
    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(30, 200, 25, 128));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(30, 200, 25, 255));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(30, 200, 25, 255));
    float btnWidth = ImGui::CalcTextSize("Generate C++ Code").x + ImGui::GetStyle().FramePadding.x * 2.0f;
    if (ImGui::Button("Call", ImVec2(btnWidth, 0)))
    {
        auto paramsInfo = method->getParamsInfo();
        auto params = paramMap[method];
        auto arrayParams = (paramsInfo.size() > 0) ? new Il2CppObject *[paramsInfo.size()] : nullptr;

        bool hasParams = true;
        Il2CppObject *thisParam = nullptr;
        if (!methodIsStatic && !thiz)
        {
            if (params["this"].value.empty())
            {
                hasParams = false;
            }
            else
            {
                thisParam = params["this"].object;
                LOGD("this = %s", params["this"].value.c_str());
            }
        }
        else if (thiz)
        {
            thisParam = thiz;
        }

        for (int k = 0; k < paramsInfo.size(); k++)
        {
            auto &[name, type] = paramsInfo[k];

            char paramKey[64]{0};
            sprintf(paramKey, "%p%s%d", method, name, k);
            auto &param = params[paramKey];
            LOGD("%s %s = %s", type->getName(), name, param.value.c_str());
            if (!param.value.empty())
            {
                try {
                    if (strcmp(type->getName(), "System.Int32") == 0)
                    {
                        ValueType<int> value{std::stoi(param.value)};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.Int64") == 0)
                    {
                        ValueType<long> value{std::stol(param.value)};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.UInt32") == 0)
                    {
                        ValueType<unsigned int> value{static_cast<unsigned int>(std::stoul(param.value))};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.UInt64") == 0)
                    {
                        ValueType<unsigned long> value{std::stoul(param.value)};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.Single") == 0)
                    {
                        ValueType<float> value{std::stof(param.value)};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.Double") == 0)
                    {
                        ValueType<double> value{std::stod(param.value)};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (strcmp(type->getName(), "System.Boolean") == 0)
                    {
                        ValueType<int> value{param.value == "True" ? 1 : 0};
                        auto boxedValue = value.box(type->getClass());
                        arrayParams[k] = boxedValue;
                    }
                    else if (type->isEnum())
                    {
                        arrayParams[k] = type->getClass()
                                             ->getField(param.value.c_str())
                                             ->getStaticValue<ValueType<int>>()
                                             .box(type->getClass());
                    }
                    else if (strcmp(type->getName(), "System.String") == 0)
                    {
                        arrayParams[k] = Il2cpp::NewString(param.value.c_str());
                    }
                    else if (param.object)
                    {
                        arrayParams[k] = param.object;
                    }
                    else
                    {
                        LOGD("Unhandled type: %s %s", type->getName(), name);
                    }
                } catch (...) {
                    LOGE("Failed to parse param %s", name);
                    hasParams = false;
                    break;
                }
            }
            else
            {
                hasParams = false;
            }
        }
        if (hasParams)
        {
            Il2CppObject *result = nullptr;

            if (strcmp(method->getName(), ".ctor") != 0 && thisParam &&
                Il2cpp::GetClassType(thisParam->klass)->isValueType())
            {
                auto thizz = Il2cpp::GetUnboxedValue(thisParam);
                result = Il2cpp::RuntimeInvokeConvertArgs(method, thizz, arrayParams, paramsInfo.size());
            }
            else
            {
                result = Il2cpp::RuntimeInvokeConvertArgs(method, thisParam, arrayParams, paramsInfo.size());
            }
            LOGPTR(result);
            if (result && strcmp(method->getName(), ".ctor") != 0)
            {
                auto resultType = Il2cpp::GetClassType(result->klass);
                if (resultType->isPrimitive())
                {
                    std::vector<uintptr_t> visited;
                    auto j = result->dump(visited, 1);
                    callResults.at(method).push_back(std::pair{j.begin().value().dump(), nullptr});
                }
                else if (strcmp(resultType->getName(), "System.String") == 0)
                {
                    callResults.at(method).push_back({((Il2CppString *)result)->to_string(), nullptr});
                }
                else if (resultType->isEnum())
                {
                    callResults.at(method).push_back(
                        {result->invoke_method<Il2CppString *>("ToString")->to_string(), nullptr});
                }
                else
                {
                    if (resultType->isValueType())
                    {
                        Il2cpp::GC::KeepAlive(result); // does this actually work?
                    }
                    auto toString = result->klass->getMethod("ToString", 0);
                    if (toString)
                    {
                        Il2CppString *str = nullptr;
                        if (resultType->isValueType())
                        {
                            auto thizz = Il2cpp::GetUnboxedValue(result);
                            // str = toString->invoke_static<Il2CppString *>(thizz);
                            str = (Il2CppString *)Il2cpp::RuntimeInvokeConvertArgs(toString, thizz, nullptr, 0);
                        }
                        else
                        {
                            str = toString->invoke_static<Il2CppString *>(result);
                        }
                        if (str)
                        {
                            callResults.at(method).push_back({str->to_string(), result});
                        }
                        else
                        {
                            callResults.at(method).push_back({"the call returned null", result});
                        }
                    }
                    else
                    {
                        char resultStr[16]{0};
                        sprintf(resultStr, "%p", result);
                        callResults.at(method).push_back({resultStr, result});
                    }
                }
                savedSet[resultType->getClass()].insert(result);
                // setJsonObject(result);
            }
            else
            {
                callResults.at(method).push_back({"the call returned null", nullptr});
            }
        }
        else
        {
            LOGE("Not all params are set!");
        }
        if (arrayParams)
            delete[] arrayParams;
    }
    ImGui::PopStyleColor(3);
    if (!callResults.at(method).empty())
    {
        ImGui::Separator();
        ImGui::Text("Call Results:");
        for (auto [callResult, object] : callResults.at(method))
        {
            if (object)
            {
                if (ImGui::Button(callResult.c_str()))
                {
                    setJsonObject(object);
                }
            }
            else
            {
                ImGui::Text("%s", callResult.c_str());
            }
            ImGui::Separator();
        }
        // ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(200, 30, 25, 128));
        // ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(200, 30, 25,
        // 255)); ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(200, 30, 25,
        // 255)); if (ImGui::Button("Clear##CallResults",
        //                   ImVec2(ImGui::GetIO().DisplaySize.x / 3.f, 0)))
        // {
        //     callResults.at(method).clear();
        // }
        // ImGui::PopStyleColor(3);
    }
}

bool ClassesTab::isMethodHooked(MethodInfo *method)
{
    return hookerMap.find(method->methodPointer) != hookerMap.end();
}

void ClassesTab::PatcherView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                             Il2CppObject *thiz)
{
    /* {
        if (isMethodHooked(method))
        {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Can't patch while hooked!");
            return;
        }
    } */

    auto &o = oMap[method];
    auto type = method->getReturnType();
    if (strcmp(type->getName(), "System.Int16") == 0 || strcmp(type->getName(), "System.Int32") == 0 ||
        strcmp(type->getName(), "System.Int64") == 0 || strcmp(type->getName(), "System.UInt16") == 0 ||
        strcmp(type->getName(), "System.UInt32") == 0 || strcmp(type->getName(), "System.UInt64") == 0 ||
        strcmp(type->getName(), "System.Single") == 0 || strcmp(type->getName(), "System.Boolean") == 0 ||
        strcmp(type->getName(), "System.String") == 0 || type->isEnum())
    {
        if (ImGui::Button("Patch return value"))
        {
            ImGui::OpenPopup("HookReturnValuePopup");
        }
        if (!o.text.empty())
        {
            ImGui::SameLine();
            ImGui::Text("-> %s", o.text.c_str());
        }
    }
    else if (strcmp(type->getName(), "System.Void") == 0)
    {
        std::lock_guard guard(oMapMtx);
        if (o.text.empty())
        {
            if (ImGui::Button("NOP"))
            {
                Patcher p{method};
                p.ret();
                o.patchedBytes = p.getCode();
                // If bytes was empty (no hook backup), save the original bytes before patching
                auto backup = p.patch();
                if (o.bytes.empty())
                    o.bytes = backup;
                o.text = "NOP";
            }
        }
        else
        {
            if (ImGui::Button("Restore"))
            {
                memcpy(method->methodPointer, o.bytes.data(), o.bytes.size());
                o.bytes.clear();
                o.patchedBytes.clear();
                o.text.clear();
            }
        }
    }
    else
    {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 50, 50, 255));
        ImGui::Text("Not supported!");
        ImGui::PopStyleColor();
    }
    if (ImGui::BeginPopup("HookReturnValuePopup"))
    {
        ImGui::Text("Change return value");
        ImGui::PushID(type);
        char label[64]{0};
        bool isPatched = false;
        {
            std::lock_guard guard(oMapMtx);
            isPatched = !o.text.empty();
        }

        if (isPatched)
        {
            sprintf(label, "%s", "Restore");
        }
        else
        {
            sprintf(label, "%s", type->getName());
        }
        if (ImGui::Button(label))
        {
            if (isPatched)
            {
                std::lock_guard guard(oMapMtx);
                memcpy(method->methodPointer, o.bytes.data(), o.bytes.size());
                o.bytes.clear();
                o.patchedBytes.clear();
                o.text.clear();
            }
            else
            {
                if (strcmp(type->getName(), "System.Int16") == 0 || strcmp(type->getName(), "System.Int32") == 0 ||
                    strcmp(type->getName(), "System.Int64") == 0 || strcmp(type->getName(), "System.UInt16") == 0 ||
                    strcmp(type->getName(), "System.UInt32") == 0 || strcmp(type->getName(), "System.UInt64") == 0 ||
                    strcmp(type->getName(), "System.Single") == 0 || strcmp(type->getName(), "System.Boolean") == 0 ||
                    strcmp(type->getName(), "System.String") == 0)
                {
                    if (strcmp(type->getName(), "System.Boolean") == 0)
                    {
                        poper.Open("BooleanSelector",
                                   [method](const std::string &b)
                                   {
                                       using namespace asmjit;
                                       Patcher p{method};
                                       bool value = b == "True";
                                       p.movBool(value);
                                       p.ret();

                                       if (oMap[method].text.empty())
                                       {
                                           oMap[method].patchedBytes = p.getCode();
                                           auto backup = p.patch();
                                           if (oMap[method].bytes.empty())
                                               oMap[method].bytes = backup;
                                           oMap[method].text = b;
                                       }
                                       else
                                       {
                                           LOGE("oMap.text is not empty for %s", method->getName());
                                       }
                                   });
                    }
                    else
                    {
                        auto typ = type;
                        auto m = method;
                        Keyboard::Open(
                            [typ, method = m](const std::string &text)
                            {
                                auto isString = strcmp(typ->getName(), "System.String") == 0;
                                if (text.empty())
                                    return;

                                auto type = typ;
                                Patcher p{method};
                                // auto &assembler = p.assembler;
                                if (strcmp(type->getName(), "System.Int16") == 0)
                                {
                                    int16_t value = std::stoi(text);
                                    p.movInt16(value);
                                }
                                else if (strcmp(type->getName(), "System.UInt16") == 0)
                                {
                                    unsigned short value = std::stoi(text);
                                    p.movUInt16(value);
                                }
                                else if (strcmp(type->getName(), "System.Int32") == 0)
                                {
                                    int value{std::stoi(text)};
                                    p.movInt32(value);
                                }
                                else if (strcmp(type->getName(), "System.UInt32") == 0)
                                {
                                    unsigned int value{static_cast<unsigned int>(std::stoul(text))};
                                    p.movUInt32(value);
                                }
                                else if (strcmp(type->getName(), "System.Int64") == 0)
                                {
                                    long value{std::stol(text)};
                                    p.movInt64(value);
                                }
                                else if (strcmp(type->getName(), "System.UInt64") == 0)
                                {
                                    unsigned long value{std::stoul(text)};
                                    p.movUInt64(value);
                                }
                                else if (strcmp(type->getName(), "System.Single") == 0)
                                {
                                    float value = std::stof(text);
                                    p.movFloat(value);
                                }
                                else if (isString)
                                {
                                    p.movPtr(Il2cpp::NewString(text.c_str()));
                                }

                                p.ret();

                                if (oMap[method].text.empty())
                                {
                                    oMap[method].patchedBytes = p.getCode();
                                    auto backup = p.patch();
                                    if (oMap[method].bytes.empty())
                                        oMap[method].bytes = backup;
                                    oMap[method].text = text;
                                }
                                else
                                {
                                    LOGE("oMap.text is not empty for %s", method->getName());
                                }
                            },
                            true);
                    }
                }
                else if (type->isEnum())
                {
                    poper.Open(
                        "EnumSelector",
                        [method, type](const std::string &result)
                        {
                            int value = type->getClass()->getField(result.c_str())->getStaticValue<int>();

                            using namespace asmjit;
                            Patcher p{method};
                            p.movInt16(value);
                            p.ret();

                            if (oMap[method].text.empty())
                            {
                                oMap[method].patchedBytes = p.getCode();
                                auto backup = p.patch();
                                if (oMap[method].bytes.empty())
                                    oMap[method].bytes = backup;
                                oMap[method].text = result;
                            }
                            else
                            {
                                LOGE("oMap.text is not empty for %s", method->getName());
                            }
                        },
                        type);
                }
            }
        }
        // if (ImGui::BeginPopup("BooleanSelector"))
        // {
        //     if (ImGui::Button("True"))
        //     {
        //         using namespace asmjit;
        //         Patcher p{method};
        //         p.movBool(true);
        //         p.ret();

        //         if (oMap[method].bytes.empty())
        //         {
        //             oMap[method].bytes = p.patch();
        //             oMap[method].text = "True";
        //         }
        //         else
        //         {
        //             LOGE("oMap is not empty for %s", method->getName());
        //         }

        //         ImGui::CloseCurrentPopup();
        //     }
        //     if (ImGui::Button("False"))
        //     {
        //         using namespace asmjit;
        //         Patcher p{method};
        //         p.movBool(false);
        //         p.ret();

        //         if (oMap[method].bytes.empty())
        //         {
        //             oMap[method].bytes = p.patch();
        //             oMap[method].text = "False";
        //         }
        //         else
        //         {
        //             LOGE("oMap is not empty for %s", method->getName());
        //         }
        //         ImGui::CloseCurrentPopup();
        //     }
        //     ImGui::EndPopup();
        // }
        // // ImGui::SetNextWindowSize(ImVec2(0, io.DisplaySize.y / 3.f));
        // ImGui::SetNextWindowSizeConstraints(ImVec2(-1, 0.f), ImVec2(-1, io.DisplaySize.y / 3.f));
        // if (ImGui::BeginPopup("EnumSelector")) // assume the current type is enum
        // {
        //     auto klass = type->getClass();
        //     for (auto field : klass->getFields())
        //     {
        //         auto fieldType = field->getType();
        //         if (Il2cpp::GetTypeIsStatic(fieldType) ||
        //             Il2cpp::GetFieldFlags(field) & FIELD_ATTRIBUTE_STATIC)
        //         {
        //             auto fieldName = field->getName();
        //             if (ImGui::Button(fieldName))
        //             {
        //                 int value = type->getClass()->getField(fieldName)->getStaticValue<int>();

        //                 using namespace asmjit;
        //                 Patcher p{method};
        //                 p.movInt16(value);
        //                 p.ret();

        //                 if (oMap[method].bytes.empty())
        //                 {
        //                     oMap[method].bytes = p.patch();
        //                     oMap[method].text = fieldName;
        //                 }
        //                 else
        //                 {
        //                     LOGE("oMap is not empty for %s", method->getName());
        //                 }
        //                 ImGui::CloseCurrentPopup();
        //             }
        //         }
        //     }
        //     ImGui::EndPopup();
        // }
        ImGui::PopID();
        ImGui::EndPopup();
    }
}
    // if (ImGui::Button("Patch"))
    // {
    //     using namespace asmjit;

    //     CodeHolder code;
    //     code.init(Environment(Arch::kAArch64));

    //     a64::Assembler assembler(&code);
    //     int a = 999;
    //     assembler.movz(a64::w0, 191);
    //     assembler.ret(a64::x30);

    //     std::vector<char> bytes;
    //     for (auto s : code.sections())
    //     {
    //         for (auto c : s->buffer())
    //         {
    //             LOGD("0x%X", c);
    //             bytes.push_back(c);
    //         }
    //     }
    //     auto rawBytes = bytes.data();
    //     auto protect = KittyMemory::ProtectAddr((void *)method->methodPointer,
    //                                             sizeof(method->methodPointer),
    //                                             PROT_READ | PROT_WRITE |
    //                                             PROT_EXEC);
    //     LOGINT(protect);
    //     auto src = method->methodPointer;
    //     memcpy((void *)src, (void *)rawBytes, sizeof(method->methodPointer));
    // }

void ClassesTab::HookerView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                            Il2CppObject *thiz)
{
    /* {
        bool patched = false;
    {
        std::lock_guard guard(oMapMtx);
        patched = !oMap[method].text.empty();
    }
        if (patched)
        {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "Can't hook while patched!");
            return;
        }
    } */
    auto it = hookerMap.find(method->methodPointer);
    bool hooked = it != hookerMap.end();
    char label[16];
    if (!hooked)
    {
        sprintf(label, "Trace");
    }
    else
    {
        sprintf(label, "Restore");
        auto value = it->second.hitCount;
        ImGui::Text("Hit Count %d", value);
        ImGui::Separator();
    }
    if (ImGui::Button(label))
    {
        Tool::ToggleHooker(method);
        it = hookerMap.find(method->methodPointer);
        hooked = it != hookerMap.end();
    }
    ImGui::Separator();
    if (hooked)
    {
        auto &backtraced = it->second.backtraced;
        if (!it->second.backtracing)
        {
            if (ImGui::Button("Backtrace"))
            {
                it->second.backtracing = true;
            }
        }

        if (backtraced.empty())
        {
            ImGui::Text("Method has not been called");
        }
        else
        {
            ImGui::Text("Backtraced methods :");

            for (auto &result : backtraced)
            {
                for (auto &r : result)
                {
                    ImGui::Text("%s", r.c_str());
                }
                ImGui::PushStyleColor(ImGuiCol_Separator, IM_COL32(50, 255, 100, 255));
                ImGui::Separator();
                ImGui::PopStyleColor();
            }
        }
    }
}

bool ClassesTab::MethodViewer(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                              Il2CppObject *thiz, bool includeInflated)
{
    bool zeroPointer = method->methodPointer == nullptr;

    if (callResults.find(method) == callResults.end())
    {
        callResults.emplace(method, (size_t)5);
    }

    bool methodIsStatic = Il2cpp::GetIsMethodStatic(method);

    char treeLabel[512]{0};
    sprintf(treeLabel, "%s %s(%zu)###", method->getReturnType()->getName(), method->getName(), paramsInfo.size());
    int pushedColor = 0;
    if (methodIsStatic)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 200, 100, 255));
        pushedColor++;
        Util::prependStringToBuffer(treeLabel, "static ");
    }
    bool hooked = false;
    int hitCount = 0;
    {
        std::lock_guard guard(hookerMtx);
        auto it = hookerMap.find(method->methodPointer);
        hooked = it != hookerMap.end();
        if (hooked)
            hitCount = it->second.hitCount;
    }
    bool patched = false;
    {
        std::lock_guard guard(oMapMtx);
        patched = !oMap[method].text.empty();
    }

    // sprintf(treeLabel, "%s##%p", treeLabel, method + j);
    if (zeroPointer)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 100, 100, 255));
        pushedColor++;
    }
    if (patched || hooked)
    {
        ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(25, 255, 125, 255));
        pushedColor++;
        if (hooked)
        {
            char hitLabel[64]{0};
            sprintf(hitLabel, "Hit Count %d | ", hitCount);
            Util::prependStringToBuffer(treeLabel, hitLabel);
        }
        else if (patched)
        {
            auto text = oMap[method].text;
            if (!text.empty())
            {
                char buff[64]{0};
                sprintf(buff, "Returns %s | ", text.c_str());
                Util::prependStringToBuffer(treeLabel, buff);
            }
        }
    }
    bool state = ImGui::TreeNode(treeLabel);
    if (state)
    {
        if (pushedColor)
        {
            ImGui::PopStyleColor(pushedColor);
            pushedColor = 0;
        }

        if (ImGui::BeginTabBar("##methoder"))
        {
            if (ImGui::BeginTabItem("Caller"))
            {
                CallerView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Patcher"))
            {
                PatcherView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Tracer"))
            {
                HookerView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("C++ Code"))
            {
                CodeView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Hex Viewer"))
            {
                HexView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Assembly View"))
            {
                AssemblyView(klass, method, paramsInfo, thiz);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::TreePop();
    }
    poper.Update();
    ImGui::PopStyleColor(pushedColor);
    return state;
}

void ClassesTab::CodeView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                          Il2CppObject *thiz)
{
    if (ImGui::Button("C++ Hook Code"))
    {
        ImGui::OpenPopup("CodeGeneratorPopup");
    }

    ShowCodePopup(method);
}

void ClassesTab::HexView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                         Il2CppObject *thiz)
{
    if (method->methodPointer == nullptr)
    {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "Method pointer is null");
        return;
    }

    int &count = hexViewCount[method];
    if (count <= 0)
        count = 16;
    ImGui::SliderInt("Bytes to show", &count, 1, 100);

    auto &o = oMap[method];
    bool isPatched = !o.bytes.empty();

    std::string hexStr;
    char buf[8];

    uint8_t *ptr = (uint8_t *)method->methodPointer;

    ImGui::BeginChild("##HexViewerArea", ImVec2(0, 150 * ImGui::GetFont()->Scale), true);
    for (int i = 0; i < count; i++)
    {
        uint8_t currentByte = ptr[i];
        sprintf(buf, "%02X", currentByte);

        bool highlighted = false;
        if (isPatched && i < (int)o.bytes.size())
        {
            if (currentByte != o.bytes[i])
            {
                highlighted = true;
            }
        }

        if (highlighted)
            ImGui::TextColored(ImVec4(0, 1, 0, 1), "%s", buf);
        else
            ImGui::Text("%s", buf);

        hexStr += buf;
        if (i < count - 1)
            hexStr += " ";

        if ((i + 1) % 8 != 0 && i < count - 1)
            ImGui::SameLine();
    }
    ImGui::EndChild();

    if (ImGui::Button("Copy Hex"))
    {
        ImGui::SetClipboardText(hexStr.c_str());
        Tool::AddNotification("Success", "Hex copied to clipboard!", true, 2.0f);
    }
}

void ClassesTab::AssemblyView(Il2CppClass *klass, MethodInfo *method, const MethodParamList &paramsInfo,
                              Il2CppObject *thiz)
{
    if (method->methodPointer == nullptr)
    {
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "Method pointer is null");
        return;
    }

    uintptr_t relOffset = method->getAbsAddress();
    char offsetStr[64];
    sprintf(offsetStr, "0x%llX", (unsigned long long)relOffset);
    ImGui::Text("Offset: %s", offsetStr);
    ImGui::SameLine();
    if (ImGui::Button("Copy Offset"))
    {
        ImGui::SetClipboardText(offsetStr);
        Tool::AddNotification("Success", "Offset copied to clipboard!", true, 2.0f);
    }

    auto &o = oMap[method];
    if (!o.patchedBytes.empty())
    {
        ImGui::SameLine();
        if (ImGui::Button("GG Patch"))
        {
            ImGui::OpenPopup("GGPatchPopup");
        }
        ShowGGPatchPopup(method);
    }

    auto &callerParams = paramMap[method];
    bool hasCallerValues = false;
    for (const auto& p : callerParams) if (!p.second.value.empty()) { hasCallerValues = true; break; }

    if (hasCallerValues)
    {
        ImGui::Separator();
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "Active Caller Context:");

        if (callerParams.count("this") && !callerParams.at("this").value.empty())
        {
            ImGui::BulletText("this: %s", callerParams.at("this").value.c_str());
        }

        for (int k = 0; k < paramsInfo.size(); k++)
        {
            char paramKey[64]{0};
            sprintf(paramKey, "%p%s%d", method, paramsInfo[k].first, k);
            if (callerParams.count(paramKey) && !callerParams.at(paramKey).value.empty())
            {
                ImGui::BulletText("%s: %s", paramsInfo[k].first, callerParams.at(paramKey).value.c_str());
            }
        }

    }

    csh handle;
    cs_err err;
    bool isThumb = false;
    uint8_t *codePtr = (uint8_t *)method->methodPointer;

#if defined(__aarch64__)
    err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
#else
    isThumb = (uintptr_t)codePtr & 1;
    codePtr = (uint8_t *)((uintptr_t)codePtr & ~1);
    err = cs_open(CS_ARCH_ARM, isThumb ? CS_MODE_THUMB : CS_MODE_ARM, &handle);
#endif

    if (err != CS_ERR_OK)
    {
        ImGui::Text("Failed to initialize Capstone!");
        return;
    }

    cs_insn *insn;
    // Disassemble up to 100 instructions or until we find a return
    size_t disasm_count = cs_disasm(handle, codePtr, 4 * 100, (uintptr_t)codePtr, 100, &insn);

    if (disasm_count > 0)
    {
        auto &o = oMap[method];
        bool isPatched = !o.bytes.empty();

        std::string asmStr;
        ImGui::BeginChild("##AssemblyViewerArea", ImVec2(ImGui::GetContentRegionAvail().x, 350 * ImGui::GetFont()->Scale), true, ImGuiWindowFlags_HorizontalScrollbar);
        for (size_t i = 0; i < disasm_count; i++)
        {
            char line[512];

            // Calculate relative offset (+0x0, +0x4, etc.)
            uintptr_t rel_off = insn[i].address - (uintptr_t)codePtr;

            // Format raw hex bytes
            char bytes_str[32] = "";
            for (size_t j = 0; j < insn[i].size; j++) {
                char b[4];
                sprintf(b, "%02X ", insn[i].bytes[j]);
                strcat(bytes_str, b);
            }
            // Align columns
            while (strlen(bytes_str) < 13) strcat(bytes_str, " ");

            sprintf(line, "+0x%04X\t%s\t%s\t\t%s", (unsigned int)rel_off, bytes_str, insn[i].mnemonic, insn[i].op_str);

            bool highlighted = false;
            if (isPatched)
            {
                size_t instr_offset = insn[i].address - (uintptr_t)codePtr;
                for (size_t j = 0; j < insn[i].size; j++)
                {
                    size_t byte_idx = instr_offset + j;
                    if (byte_idx < o.bytes.size())
                    {
                        // In memory it's the patched byte, in o.bytes it's the original byte
                        if (codePtr[byte_idx] != o.bytes[byte_idx])
                        {
                            highlighted = true;
                            break;
                        }
                    }
                }
            }

            if (highlighted)
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "%s", line);
            else
                ImGui::Text("%s", line);

            asmStr += line;
            asmStr += "\n";

            // Stop at common return instructions to "only show this method"
            if (strcmp(insn[i].mnemonic, "ret") == 0 ||
                strcmp(insn[i].mnemonic, "bx") == 0 ||
                (strcmp(insn[i].mnemonic, "pop") == 0 && strstr(insn[i].op_str, "pc") != nullptr))
            {
                disasm_count = i + 1;
                break;
            }
        }
        ImGui::EndChild();

        if (ImGui::Button("Copy Assembly"))
        {
            ImGui::SetClipboardText(asmStr.c_str());
            Tool::AddNotification("Success", "Assembly copied to clipboard!", true, 2.0f);
        }

        cs_free(insn, disasm_count);
    }
    else
    {
        ImGui::Text("Failed to disassemble code at %p", codePtr);
    }

    cs_close(&handle);
}

void ClassesTab::ShowCodePopup(MethodInfo *method)
{
    static ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowSizeConstraints(ImVec2(io.DisplaySize.x * 0.8f, 0), ImVec2(io.DisplaySize.x * 0.95f, io.DisplaySize.y * 0.8f));
    if (ImGui::BeginPopup("CodeGeneratorPopup"))
    {
        std::string code = GenerateCppCode(method);

        ImGui::Text("Generated C++ Code:");
        ImGui::Separator();

        ImGui::BeginChild("CodeArea", ImVec2(ImGui::GetContentRegionAvail().x, 300 * ImGui::GetFont()->Scale));
        ImGui::PushTextWrapPos(ImGui::GetCursorPos().x + ImGui::GetContentRegionAvail().x);
        ImGui::TextUnformatted(code.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndChild();

        ImGui::Separator();
        if (ImGui::Button("Copy to Clipboard", ImVec2(ImGui::GetContentRegionAvail().x, 0)))
        {
            ImGui::SetClipboardText(code.c_str());
            Tool::AddNotification("Success", "Code copied to clipboard!", true, 2.0f);
        }

        if (ImGui::Button("Close", ImVec2(ImGui::GetContentRegionAvail().x, 0)))
        {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

std::string ClassesTab::GenerateCppCode(MethodInfo *method)
{
    std::stringstream ss;
    uintptr_t offset = method->getAbsAddress();
    std::string methodName = method->getName();
    std::string className = method->getClass()->getName();

    // Remove invalid characters for C++ variable name
    std::string safeMethodName = methodName;
    std::string charsToReplace = ".<>` ";
    for (char c : charsToReplace) {
        std::replace(safeMethodName.begin(), safeMethodName.end(), c, '_');
    }

    auto convertType = [](Il2CppType* type) -> std::string {
        std::string name = type->getName();
        if (name == "System.Void") return "void";
        if (name == "System.Boolean") return "bool";
        if (name == "System.Byte") return "unsigned char";
        if (name == "System.SByte") return "signed char";
        if (name == "System.Int16") return "short";
        if (name == "System.UInt16") return "unsigned short";
        if (name == "System.Int32") return "int";
        if (name == "System.UInt32") return "uint";
        if (name == "System.Int64") return "long long";
        if (name == "System.UInt64") return "ulong";
        if (name == "System.Single") return "float";
        if (name == "System.Double") return "double";
        if (name == "System.String") return "monoString*";
        if (type->isEnum()) return "int";
        if (!type->isPrimitive()) return "void*";
        return name;
    };

    std::string returnTypeName = convertType(method->getReturnType());
    auto params = method->getParamsInfo();
    bool isVoid = strcmp(method->getReturnType()->getName(), "System.Void") == 0;

    ss << "//" << className << "::" << methodName << "\n";
    ss << "bool Is" << safeMethodName << " = false;\n";
    ss << returnTypeName << " (*old_" << safeMethodName << ")(void* instance";
    for (auto& p : params) ss << ", " << convertType(p.second) << " " << p.first;
    ss << ");\n";

    ss << returnTypeName << " " << safeMethodName << "(void* instance";
    for (auto& p : params) ss << ", " << convertType(p.second) << " " << p.first;
    ss << ") {\n";
    ss << "\tif (instance != NULL) {\n";
    ss << "\t\tif (Is" << safeMethodName << ") {\n";

    auto &o = oMap[method];
    std::string patchValue = o.text;

    auto rawReturnType = method->getReturnType()->getName();
    if (isVoid) {
        if (patchValue == "NOP") {
            ss << "\t\t\treturn;\n";
        } else {
            auto &callerParams = paramMap[method];
            bool hasCallerValues = false;
            for (int k = 0; k < (int)params.size(); k++) {
                char paramKey[64]{0};
                sprintf(paramKey, "%p%s%d", method, params[k].first, k);
                if (callerParams.count(paramKey) && !callerParams[paramKey].value.empty()) {
                    hasCallerValues = true;
                    break;
                }
            }

            if (hasCallerValues) {
                ss << "\t\t\told_" << safeMethodName << "(instance";
                for (int k = 0; k < (int)params.size(); k++) {
                    char paramKey[64]{0};
                    sprintf(paramKey, "%p%s%d", method, params[k].first, k);
                    std::string val = params[k].first;
                    if (callerParams.count(paramKey) && !callerParams[paramKey].value.empty()) {
                        auto &cp = callerParams[paramKey];
                        auto paramType = params[k].second;
                        std::string typeName = paramType->getName();

                        if (typeName == "System.Boolean") {
                            val = (cp.value == "True" ? "true" : "false");
                        } else if (typeName == "System.String") {
                            val = "il2cpp_string_new(OBFUSCATE(\"" + cp.value + "\"))";
                        } else if (!paramType->isPrimitive() && !paramType->isEnum()) {
                            val = "NULL"; // Avoid hardcoded runtime addresses like 0x7cdbc19910
                        } else {
                            val = cp.value;
                        }
                    }
                    ss << ", " << val;
                }
                ss << ");\n";
                ss << "\t\t\treturn;\n";
            } else {
                ss << "\t\t\t// Do something\n";
            }
        }
    } else {
        auto returnTypeObj = method->getReturnType();
        if (!patchValue.empty()) {
            if (strcmp(rawReturnType, "System.Boolean") == 0) {
                ss << "\t\t\treturn " << (patchValue == "True" ? "true" : "false") << "; // true/false.\n";
            } else if (strcmp(rawReturnType, "System.String") == 0) {
                ss << "\t\t\treturn il2cpp_string_new(OBFUSCATE(\"" << patchValue << "\"));\n";
            } else if (!returnTypeObj->isPrimitive() && !returnTypeObj->isEnum()) {
                ss << "\t\t\treturn NULL;\n";
            } else {
                ss << "\t\t\treturn " << patchValue << ";\n";
            }
        } else {
            if (callResults.count(method) && !callResults.at(method).empty()) {
                std::string lastResult = callResults.at(method).back().first;
                if (lastResult != "the call returned null") {
                    if (strcmp(rawReturnType, "System.Boolean") == 0) {
                        ss << "\t\t\treturn " << (lastResult == "true" || lastResult == "True" ? "true" : "false") << ";\n";
                    } else if (strcmp(rawReturnType, "System.String") == 0) {
                        ss << "\t\t\treturn il2cpp_string_new(OBFUSCATE(\"" << lastResult << "\"));\n";
                    } else if (!returnTypeObj->isPrimitive() && !returnTypeObj->isEnum()) {
                        ss << "\t\t\treturn NULL;\n";
                    } else {
                        ss << "\t\t\treturn " << lastResult << ";\n";
                    }
                } else {
                    ss << "\t\t\t// return ...;\n";
                }
            } else {
                ss << "\t\t\t// return ...;\n";
            }
        }
    }

    ss << "\t\t}\n";
    ss << "\t}\n";
    ss << "\treturn old_" << safeMethodName << "(instance";
    for (size_t i = 0; i < params.size(); ++i) {
        ss << "," << params[i].first;
    }
    ss << ");\n";
    ss << "}\n\n";

    ss << "DobbyHook((void *)getAbsoluteAddress(targetLibName, 0x" << std::hex << std::uppercase << offset << "), (void *) " << safeMethodName << ", (void **) &old_" << safeMethodName << ");";

    return ss.str();
}

void ClassesTab::ShowGGPatchPopup(MethodInfo *method)
{
    static ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowSizeConstraints(ImVec2(io.DisplaySize.x * 0.8f, 0), ImVec2(io.DisplaySize.x * 0.95f, io.DisplaySize.y * 0.8f));
    if (ImGui::BeginPopup("GGPatchPopup"))
    {
        std::string code = GenerateGGPatchCode(method);

        ImGui::Text("Generated GG Patch Script:");
        ImGui::Separator();

        ImGui::BeginChild("GGCodeArea", ImVec2(ImGui::GetContentRegionAvail().x, 300 * ImGui::GetFont()->Scale));
        ImGui::PushTextWrapPos(ImGui::GetCursorPos().x + ImGui::GetContentRegionAvail().x);
        ImGui::TextUnformatted(code.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndChild();

        ImGui::Separator();
        if (ImGui::Button("Copy to Clipboard", ImVec2(ImGui::GetContentRegionAvail().x, 0)))
        {
            ImGui::SetClipboardText(code.c_str());
            Tool::AddNotification("Success", "Script copied to clipboard!", true, 2.0f);
        }

        if (ImGui::Button("Close", ImVec2(ImGui::GetContentRegionAvail().x, 0)))
        {
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

std::string ClassesTab::GenerateGGPatchCode(MethodInfo *method)
{
    std::stringstream ss;
    uintptr_t relOffset = method->getAbsAddress();
    auto &o = oMap[method];

    // Auto-detect working ELF index for libil2cpp.so within its own ranges list
    int elfIndex = 1;
    FILE *fp = fopen("/proc/self/maps", "rt");
    if (fp) {
        char line[512];
        int il2cppSegmentIdx = 0;
        uintptr_t lastEnd = 0;
        char lastPerms[8] = "";

        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, targetLibName)) {
                uintptr_t start, end;
                char perms[8];
                if (sscanf(line, "%lx-%lx %s", &start, &end, perms) < 3) continue;

                // Game Guardian merges adjacent segments of the same file if perms match
                if (start != lastEnd || strcmp(perms, lastPerms) != 0) {
                    il2cppSegmentIdx++;
                }

                if (strstr(perms, "x")) { // Executable segment
                    elfIndex = il2cppSegmentIdx;
                    break;
                }

                lastEnd = end;
                strcpy(lastPerms, perms);
            }
        }
        fclose(fp);
    }

    ss << "-- GG Script Header\n";
    ss << "function setValues(address, flags, value) gg.setValues({[1] = {address = address, flags = flags, value = value}}) end\n";
    ss << "il2cpp = gg.getRangesList(\"" << (const char*)targetLibName << "\")[" << elfIndex << "].start\n\n";

    auto addPatchLine = [&](uintptr_t offset, const std::string& asmLine) {
        ss << "setValues(il2cpp + 0x" << std::hex << std::uppercase << relOffset;
        uintptr_t diff = offset - relOffset;
        if (diff > 0) ss << " + " << std::dec << diff;
        ss << ", 4, \"~A" << (sizeof(void*) == 8 ? "8 " : "4 ") << asmLine << "\")\n";
    };

    if (!o.patchedBytes.empty()) {
        csh handle;
        cs_err err;
#if defined(__aarch64__)
        err = cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle);
#else
        err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
#endif
        if (err == CS_ERR_OK) {
            cs_insn *insn;
            size_t count = cs_disasm(handle, o.patchedBytes.data(), o.patchedBytes.size(), 0, 0, &insn);
            if (count > 0) {
                ss << "-- GG Patch for " << method->getName() << " (from Tool Patch)\n";
                for (size_t i = 0; i < count; i++) {
                    std::string instruction = std::string(insn[i].mnemonic) + " " + insn[i].op_str;
                    std::transform(instruction.begin(), instruction.end(), instruction.begin(), ::toupper);
                    addPatchLine(relOffset + insn[i].address, instruction);
                }
                cs_free(insn, count);
            }
            cs_close(&handle);
        }
    } else {
        // No hardware patch, try generating one from Caller Context
        auto rawReturnType = method->getReturnType()->getName();
        bool isVoid = strcmp(rawReturnType, "System.Void") == 0;

        if (!isVoid && callResults.count(method) && !callResults.at(method).empty()) {
            std::string lastResult = callResults.at(method).back().first;
            if (lastResult != "the call returned null") {
                ss << "-- GG Patch for " << method->getName() << " (from Caller Value)\n";
#if defined(__aarch64__)
                if (strcmp(rawReturnType, "System.Boolean") == 0) {
                    addPatchLine(relOffset, (lastResult == "true" || lastResult == "True") ? "MOV W0, #1" : "MOV W0, #0");
                    addPatchLine(relOffset + 4, "RET");
                } else if (strcmp(rawReturnType, "System.Int32") == 0 || strcmp(rawReturnType, "System.UInt32") == 0) {
                    addPatchLine(relOffset, "MOV W0, #" + lastResult);
                    addPatchLine(relOffset + 4, "RET");
                } else {
                    ss << "-- Manual edit required for type: " << rawReturnType << "\n";
                }
#endif
            }
        }
    }

    if (ss.str().find("setValues(il2cpp") == std::string::npos) {
        ss << "-- No active patch or caller value found for " << method->getName() << "\n";
    }

    return ss.str();
}




const ClassesTab::MethodParamList &ClassesTab::getCachedParams(MethodInfo *method)
{
    static std::unordered_map<MethodInfo *, MethodParamList> params;
    if (params.find(method) == params.end())
    {
        params[method] = method->getParamsInfo();
    }
    return params[method];
}

// static std::unordered_map<Il2CppClass *, bool> states;
void ClassesTab::ClassViewer(Il2CppClass *klass)
{
    if (ImGui::Button("Inspect Objects"))
    {
        ImGui::OpenPopup("DumpPopup");
    }
    {
        ImGui::SameLine();
        bool &state = states[klass];
        char label[12]{0};
        if (!state)
            sprintf(label, "Trace all");
        else
            sprintf(label, "Restore");
        if (ImGui::Button(label))
        {
            if (!state)
            {
                ImGui::OpenPopup("ConfirmPopup");
            }
            else
            {
                state = false;
                for (auto &[method, paramsInfo] : methodMap[klass])
                {
                    if (!method->methodPointer && !Il2cpp::GetIsMethodInflated(method))
                        continue;

                    Tool::ToggleHooker(method, 0);
                }
            }
        }
        if (ImGui::BeginPopup("ConfirmPopup"))
        {
            ImGui::TextColored(ImVec4(0.8, 0.8, 0, 1), "WARNING: There's a high-risk of crash");
            if (ImGui::Button("Continue?"))
            {
                state = true;
                std::thread hookThread(
                    [this, klass]
                    {
                        for (auto &[method, paramsInfo] : methodMap[klass])
                        {
                            if (!method->methodPointer && !Il2cpp::GetIsMethodInflated(method))
                                continue;

                            Tool::ToggleHooker(method, 1);
                        }
                    });
                hookThread.detach();
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }
    // ImGui::SameLine();
    // if (ImGui::Button("Add to Tracer"))
    // {
    //     tracer.push_back(klass);
    // }
    if (ImGui::BeginPopup("DumpPopup"))
    {
        ImGuiObjectSelector(ImGui::GetID("ObjectSelector"), klass, "Inspect",
                            [this](Il2CppObject *object) { setJsonObject(object); });
        ImGui::EndPopup();
    }
    ImGui::PopID();
    ImGui::Separator();

    int j = 0;
    for (auto &[method, paramsInfo] : methodMap[klass])
    {
        ImGui::PushID(method + j++);
        MethodViewer(klass, method, paramsInfo);
        ImGui::Separator();
        ImGui::PopID();
    }
}

void ClassesTab::Draw(int index, bool closeable)
{
    static ImGuiIO &io = ImGui::GetIO();
    char tabLabel[256];
    if (filter.empty())
    {
        sprintf(tabLabel, "Classes");
        if (index >= 0)
            sprintf(tabLabel, "Classes [%d]", index + 1);
    }
    else
    {
        sprintf(tabLabel, "%s", filter.c_str());
    }

    if ((currentlyOpened = ImGui::BeginTabItem(tabLabel, closeable ? &opened : nullptr,
                                               setOpenedTab ? ImGuiTabItemFlags_SetSelected : 0)))
    {
        setOpenedTab = false;
        ImGui::BeginDisabled(includeAllImages);
        ImGui::SetNextWindowSizeConstraints(ImVec2(0, 0), ImVec2(-1, io.DisplaySize.y / 1.5f));
        if (ImGui::BeginCombo("Image##ImageSelector", selectedImage->getName()))
        {

            for (int i = 0; i < g_Images.size(); i++)
            {
                bool selected = selectedImageIndex == i;
                if (ImGui::Selectable(g_Images[i]->getName(), selected))
                {
                    selectedImage = g_Images[i];
                    selectedImageIndex = i;
                    FilterClasses(filter);
                }
                if (selected)
                {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Checkbox("All", &includeAllImages))
        {
            FilterClasses(filter);
        }

        char filterBuf[256];
        strncpy(filterBuf, filter.c_str(), sizeof(filterBuf));
        if (ImGui::InputText("Filter", filterBuf, sizeof(filterBuf), ImGuiInputTextFlags_CallbackAlways,
                            [](ImGuiInputTextCallbackData *data)
                            {
                                ClassesTab *tab = (ClassesTab *)data->UserData;
                                if (tab->externalChanged)
                                {
                                    data->DeleteChars(0, data->BufTextLen);
                                    data->InsertChars(0, tab->filter.c_str());
                                    tab->externalChanged = false;
                                }
                                return 0;
                            },
                            this))
        {
            filter = filterBuf;
            FilterClasses(filter);
        }
        if (ImGui::IsItemClicked())
        {
            Keyboard::Open(filter.c_str(),
                           [this](const std::string &text)
                           {
                               filter = text;
                               externalChanged = true;
                               FilterClasses(filter);
                           });
        }
        ImGui::Text("Matches: %zu of %zu", filteredClasses.size(), classes.size());

        if (ImGui::Button("Filter Options"))
        {
            ImGui::OpenPopup("FilterOptions");
        }

        {
            static bool processing = false;
            ImGui::SameLine();
            char label[12]{0};
            if (!traceState)
                sprintf(label, "Trace all");
            else
                sprintf(label, "Restore");

            bool disabled = false;
            if (processing)
            {
                disabled = true; // creating variable because `processing` could be set to false and we don't call
                                 // `EndDisabled`
                ImGui::BeginDisabled();
            }
            if (ImGui::Button(label))
            {
                {
                    if (!traceState)
                    {
                        ImGui::OpenPopup("ConfirmPopup");
                    }
                    else
                    {
                        traceState = false;
                        std::thread hookThread(
                            [this]
                            {
                                LOGD("Restoring all methods...");
                                processing = true;
                                maxProgress = tracedMethods.size();
                                for (auto method : tracedMethods)
                                {
                                    Tool::ToggleHooker(method);
                                }
                                LOGD("Restored %zu methods", tracedMethods.size());
                                tracedMethods.clear();
                                processing = false;
                                maxProgress = 0;
                                progress = 0;
                                LOGD("Done");
                            });
                        hookThread.detach();
                    }
                }
            }

            if (disabled)
                ImGui::EndDisabled();

            if (ImGui::BeginPopup("ConfirmPopup"))
            {
                ImGui::TextColored(ImVec4(0.8, 0.8, 0, 1), "WARNING: There's a high-risk of crash");
                if (ImGui::Button("Continue?"))
                {
                    traceState = true;
                    std::thread hookThread(
                        [this]
                        {
                            LOGD("Tracing all methods...");
                            for (auto &klass : filteredClasses)
                            {
                                for (auto &[method, paramsInfo] : methodMap[klass])
                                {
                                    if (!method->methodPointer && !Il2cpp::GetIsMethodInflated(method))
                                        continue;

                                    maxProgress++;
                                }
                            }
                            processing = true;
                            for (auto &klass : filteredClasses)
                            {
                                states[klass] = true;
                                for (auto &[method, paramsInfo] : methodMap[klass])
                                {
                                    if (!method->methodPointer && !Il2cpp::GetIsMethodInflated(method))
                                        continue;

                                    if (Tool::ToggleHooker(method, 1))
                                    {
                                        tracedMethods.push_back(method);
                                    }
                                    progress++;
                                }
                            }
                            LOGD("Traced %zu methods", tracedMethods.size());

                            processing = false;
                            maxProgress = 0;
                            progress = 0;
                            LOGD("Done");
                        });
                    hookThread.detach();
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
            if (processing)
            {
                ImGui::SameLine();
                ImGui::Text("Processing %d of %d ...", progress, maxProgress);
            }
        }
        if (ImGui::BeginPopup("FilterOptions"))
        {
            if (ImGui::Checkbox("Case-Sensitive", &caseSensitive))
            {
                FilterClasses(filter);
            }
            ImGui::Text("Filter by ");
            ImGui::SameLine();
            if (ImGui::RadioButton("Class", filterByClass == true))
            {
                filterByClass = true;
                filterByMethod = false;
                filterByField = false;
                FilterClasses(filter);
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("Method", filterByMethod == true))
            {
                filterByClass = false;
                filterByMethod = true;
                filterByField = false;
                FilterClasses(filter);
            }
            ImGui::SameLine();
            if (ImGui::RadioButton("Field", filterByField == true))
            {
                filterByClass = false;
                filterByMethod = false;
                filterByField = true;
                FilterClasses(filter);
            }
            if (ImGui::Checkbox("Show All Classes", &showAllClasses))
            {
                FilterClasses(filter);
            }
            ImGui::EndPopup();
        }
        ImGui::Separator();
        if (!filteredClasses.empty())
        {
            ImGui::BeginChild("Child", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            for (int i = 0; i < filteredClasses.size(); i++)
            {
                auto klass = filteredClasses[i];

                bool isValueType = Il2cpp::GetClassType(klass)->isValueType();
                int pushedColor = 0;
                if (isValueType)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(222, 222, 222, 255));
                    pushedColor++;
                }
                bool collapsingHeader = ImGui::CollapsingHeader(klass->getFullName().c_str());
                if (filterByMethod && ImGui::IsItemHeld(0.7f))
                {
                    auto name = Util::extractClassNameFromTypename(klass->getFullName().c_str());
                    auto &tab = Tool::OpenNewTab();
                    tab.filter = name;
                    tab.selectedImage = klass->getImage();
                    tab.FilterClasses(tab.filter);
                }
                if (collapsingHeader)
                {
                    if (pushedColor)
                    {
                        ImGui::PopStyleColor(pushedColor);
                        pushedColor = 0;
                    }
                    ImGui::PushID(i);
                    // TODO: Rename Dump (DumpPopup and other related functions used) to Inspect
                    ClassViewer(klass);
                }
                if (pushedColor)
                {
                    ImGui::PopStyleColor(pushedColor);
                    pushedColor = 0;
                }
            }
            ImGui::ScrollWhenDraggingOnVoid();
            ImGui::EndChild();
        }
        ImGui::EndTabItem();
    }
}
void ClassesTab::DrawTabMap()
{
    for (auto it = tabMap.begin(); it != tabMap.end();)
    {
        auto &[object, visible] = *it;
        char buff[32]{0};
        sprintf(buff, "[%p]", object);

        if (!visible)
        {
            it = tabMap.erase(it);
            dataMap.erase(object);
        }
        else
        {
            if (ImGui::BeginTabItem(buff, &visible))
            {
                ImGuiJson(object);
                ImGui::EndTabItem();
            }
            ++it;
        }
    }
}

void ensureIfValueType(Il2CppObject *currentObj, std::vector<std::string> &paths, Il2CppObject *rootObj) {
    if (currentObj == rootObj)
        return;

    bool isValueType = Il2cpp::GetClassType(currentObj->klass)->isValueType();

    if (!isValueType)
        return;

    if (paths.size() > 1) {
        std::vector<std::string> pathsButLast;
        pathsButLast.assign(paths.begin(), paths.end() - 1);

        auto result = rootObj->dump(pathsButLast, true);
        Il2CppObject *beforeObject = result.first;

        auto path = paths.rbegin();

        std::istringstream iss(*path);
        std::string unused, val;
        iss >> unused >> val;

        void *unboxed = Il2cpp::GetUnboxedValue(currentObj);

        auto f = beforeObject->klass->getField(val.c_str());
        Il2cpp::SetFieldValue(beforeObject, f, unboxed);

        ensureIfValueType(beforeObject, pathsButLast, rootObj);
    } else {
        auto path = paths.begin();

        std::istringstream iss(*path);
        std::string unused, val;
        iss >> unused >> val;

        void *unboxed = Il2cpp::GetUnboxedValue(currentObj);

        auto f = rootObj->klass->getField(val.c_str());
        Il2cpp::SetFieldValue(rootObj, f, unboxed);
    }
}

void ClassesTab::ImGuiJson(Il2CppObject *rootObj)
{
    // auto &paths = tool.dataMap[object].second;
    auto &paths = getJsonPaths(rootObj);

    int indentCounter = 0;
    auto currentObj = dataMap[rootObj].first.first;
    for (auto it = paths.begin() + (paths.size() > 3 ? paths.size() - 4 : 0); it != paths.end(); ++it)
    {
        const bool isLast = std::next(it) == paths.end();
        auto key = it->c_str();
        ImGui::PushID(indentCounter);

        bool buttonPressed = false;
        bool isValueType = Il2cpp::GetClassType(currentObj->klass)->isValueType();
        if (isLast && isValueType)
        {
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(222, 222, 222, 255));
        }
        if (isLast && currentObj && savedSet[currentObj->klass].count(currentObj) == 0)
        {
            auto width = ImGui::CalcTextSize("Save").x + ImGui::GetStyle().FramePadding.x * 5.f;
            buttonPressed = ImGui::Button(key, ImVec2(ImGui::GetContentRegionAvail().x - width, 0));
            if (ImGui::IsItemHeld())
            {
                Tool::OpenNewTabFromClass(currentObj->klass);
                LOGD("OpenNewTabFromObject %p", currentObj);
            }
            ImGui::SameLine();
            char buttonLabel[32]{0};
            sprintf(buttonLabel, "Save");
            if (ImGui::Button(buttonLabel,
                              ImVec2(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().FramePadding.x, 0)))
            {
                savedSet[currentObj->klass].insert(currentObj);
            }
            if (ImGui::IsItemHovered())
            {
                ImGui::SetTooltip("%p", currentObj);
            }
        }
        else
        {
            buttonPressed =
                ImGui::Button(key, ImVec2(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().FramePadding.x, 0));
            if (ImGui::IsItemHeld())
            {
                Tool::OpenNewTabFromClass(currentObj->klass);
                LOGD("OpenNewTabFromObject %p", currentObj);
            }
        }
        if (isLast && isValueType)
        {
            ImGui::PopStyleColor();
        }
        ImGui::Indent(10.f);
        indentCounter++;
        ImGui::PopID();

        if (buttonPressed)
        {
            paths.erase(it, paths.end());
            dataMap[rootObj].first = rootObj->dump(paths);
            break;
        }
    }
    if (indentCounter)
        ImGui::Unindent(10.f * indentCounter);

    ImGui::PushStyleColor(ImGuiCol_Button, IM_COL32(100, 200, 20, 128));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, IM_COL32(100, 200, 20, 255));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, IM_COL32(100, 200, 20, 255));
    static bool doRefresh = false;
    if (ImGui::Button("Refresh", ImVec2(ImGui::GetContentRegionAvail().x, 0.0f)))
    {
        doRefresh = true;
    }
    if (doRefresh)
    {
        doRefresh = false;
        dataMap[rootObj].first = rootObj->dump(paths);
    }
    ImGui::PopStyleColor(3);

    ImGui::PushStyleColor(ImGuiCol_Separator, IM_COL32(0, 255, 100, 255));
    ImGui::Separator();
    ImGui::PopStyleColor();
    static PopUpSelector poper;
    if (ImGui::BeginTable("sometable", 1))
    {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::BeginChild("ChildJson",
                          ImVec2(0, ImGui::GetContentRegionAvail().y - (ImGui::GetFontSize() * 1.8f) * 2.f), 0,
                          ImGuiWindowFlags_HorizontalScrollbar);

        const nlohmann::ordered_json &current = getJsonObject(rootObj);
        if (current.empty())
        {
            ImGui::Text("Empty");
        }

        for (auto &[key, value] : current.items())
        {
            // int count = 0;
            if (value.is_object() || value.is_array())
            {
                if (value.is_array() && value.size() == 0)
                {
                    ImGui::Text("%s = [Empty]", key.c_str());
                }
                else if (ImGui::Button(key.c_str(), ImVec2(key.length() <= 3 ? ImGui::GetContentRegionAvail().x -
                                                                                   ImGui::GetStyle().FramePadding.x
                                                                             : 0,
                                                           0)))
                {
                    try
                    {
                        paths.push_back(key);
                        // LOGD("%s", object->dump(paths).dump().c_str());
                        dataMap[rootObj].first = rootObj->dump(paths);
                        break;
                    }
                    catch (nlohmann::json::exception &e)
                    {
                        LOGE("Json exception %s", e.what());
                    }
                    catch (std::exception &e)
                    {
                        LOGE("Exception %s", e.what());
                    }
                }
            }
            else if (value.is_string())
            {
                auto text = value.get<std::string>();
                ImGui::Text("%s = %s", key.c_str(), text.c_str());
                if (ImGui::IsItemClicked())
                {
                    std::istringstream iss(key);
                    std::string type, val;
                    iss >> type >> val;
                    if (strcmp(type.c_str(), "String") == 0)
                    {
                        Keyboard::Open(
                            text.c_str(),
                            [type = std::move(type), val = std::move(val), currentObj](const std::string &value)
                            {
                                LOGD("%s", value.c_str());
                                auto f = currentObj->klass->getField(val.c_str());
                                auto newStr = Il2cpp::NewString(value.c_str());
                                // Il2cpp::SetFieldValueObject(currentObj, f, newStr);
                                Il2cpp::SetFieldValue(currentObj, f, newStr);
                                doRefresh = true;
                            },
                            true);
                    }
                    else
                    {
                        auto field = currentObj->klass->getField(val.c_str());
                        auto fieldType = field->getType();
                        if (fieldType->isEnum())
                        {
                            poper.Open(
                                "EnumSelector",
                                [fieldType, currentObj, field](const std::string &result)
                                {
                                    int value = fieldType->getClass()->getField(result.c_str())->getStaticValue<int>();
                                    Il2cpp::SetFieldValue(currentObj, field, &value);
                                    doRefresh = true;
                                },
                                fieldType);
                        }
                    }
                }
            }
            else if (value.is_boolean())
            {
                ImGui::Text("%s = %s", key.c_str(), value.get<bool>() ? "True" : "False");
                if (ImGui::IsItemClicked())
                {
                    std::istringstream iss(key);
                    std::string _, val;
                    iss >> _ >> val;
                    poper.Open("BooleanSelector",
                               [currentObj, val, &paths, rootObj](const std::string &value)
                               {
                                   bool b = value == "True";
                                   // split key by space
                                   currentObj->setField(val.c_str(), (int)b);
                                   ensureIfValueType(currentObj, paths, rootObj);
                                   doRefresh = true;
                               });
                }
            }
            else if (value.is_number_float())
            {
                ImGui::Text("%s = %f", key.c_str(), value.get<float>());

                if (ImGui::IsItemClicked())
                {
                    std::istringstream iss(key);
                    std::string type, val;
                    iss >> type >> val;
                    Keyboard::Open(std::to_string(value.get<float>()).c_str(),
                                   [type, currentObj, val, &paths, rootObj](const std::string &text)
                                   {
                                       try {
                                           if (strcmp(type.c_str(), "Single") == 0)
                                           {
                                               float value = std::stof(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "Double") == 0)
                                           {
                                               double value = std::stod(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           ensureIfValueType(currentObj, paths, rootObj);
                                           doRefresh = true;
                                       } catch (...) {
                                           LOGE("Failed to parse float/double");
                                       }
                                   },
                                   true);
                }
            }
            else if (value.is_number())
            {
                ImGui::Text("%s = %d", key.c_str(), value.get<int>());
                if (ImGui::IsItemClicked())
                {
                    std::istringstream iss(key);
                    std::string type, val;
                    iss >> type >> val;
                    Keyboard::Open(std::to_string(value.get<int>()).c_str(),
                                   [type, currentObj, val, &paths, rootObj](const std::string &text)
                                   {
                                       try {
                                           if (strcmp(type.c_str(), "Int16") == 0)
                                           {
                                               int16_t value = std::stoi(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "UInt16") == 0)
                                           {
                                               uint16_t value = std::stoi(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "Int32") == 0)
                                           {
                                               int32_t value = std::stoi(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "UInt32") == 0)
                                           {
                                               uint32_t value = std::stoul(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "Int64") == 0)
                                           {
                                               int64_t value = std::stoll(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           else if (strcmp(type.c_str(), "UInt64") == 0)
                                           {
                                               uint64_t value = std::stoull(text);
                                               currentObj->setField(val.c_str(), value);
                                           }
                                           ensureIfValueType(currentObj, paths, rootObj);
                                           doRefresh = true;
                                       } catch (...) {
                                           LOGE("Failed to parse integer");
                                       }
                                   },
                                   true);
                }
            }
            else
            {
                ImGui::Text("Unk %s %s", key.c_str(), value.type_name());
            }
            // constexpr ImU32 colors[8] = {
            //     IM_COL32(255,50,50,255),     IM_COL32(0, 255, 0, 255),   IM_COL32(0, 0, 255, 255),
            //     IM_COL32(255, 255, 0, 255),   IM_COL32(255, 0, 255, 255), IM_COL32(0, 255, 255, 255),
            //     IM_COL32(255, 255, 255, 255), IM_COL32(0, 0, 0, 255),
            // };
            // ImGui::PushStyleColor(ImGuiCol_Separator, colors[paths.size() % 8]);
            ImGui::Separator();
            // ImGui::PopStyleColor();
        }

        ImGui::ScrollWhenDraggingOnVoid();
        ImGui::EndChild();

        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::BeginChild("bottom");
        if (ImGui::Button("Methods", ImVec2(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().FramePadding.x, 0)))
        {
            ImGui::OpenPopup("MethodPopup");
        }

        static ImGuiIO &io = ImGui::GetIO();
        ImGui::SetNextWindowSizeConstraints(ImVec2(io.DisplaySize.x / 1.2f, 0),
                                            ImVec2(io.DisplaySize.x / 1.2f, io.DisplaySize.y / 2));
        if (ImGui::BeginPopup("MethodPopup", ImGuiWindowFlags_HorizontalScrollbar))
        {
            auto text = currentObj->klass->getName();
            auto windowWidth = ImGui::GetWindowSize().x;
            auto textWidth = ImGui::CalcTextSize(text).x;
            ImGui::SetCursorPosX((windowWidth - textWidth) * 0.5f);
            ImGui::Text("%s", text);

            ImGui::Separator();

            auto &methods = buildMethodMap(currentObj->klass);
            if (methods.empty())
            {
                ImGui::Text("No methods for class %s", currentObj->klass->getName());
            }
            else
            {
                int j = 0;
                for (auto &[method, paramsInfo] : methods)
                {
                    ImGui::PushID(method + j++);
                    MethodViewer(currentObj->klass, method, paramsInfo, currentObj, true);
                    ImGui::Separator();
                    ImGui::PopID();
                }
            }
            ImGui::EndPopup();
        }

        if (ImGui::Button("Dump to file",
                          ImVec2(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().FramePadding.x, 0)))
        {
            ImGui::OpenPopup("ProceedPopUp");
        }
        if (ImGui::BeginPopup("ProceedPopUp"))
        {
            char fileName[256]{0};
            snprintf(fileName, sizeof(fileName), "dump_%s (%p).json", currentObj->klass->getName(), currentObj);
            ImGui::Text("File will be saved as %s", fileName);
            ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 50, 255));
            ImGui::Text("Note: This may take a while depending on the size of the object");
            ImGui::Text("Do not touch the screen if it's freezing!");
            ImGui::PopStyleColor();
            if (ImGui::Button("Proceed", ImVec2(ImGui::GetContentRegionAvail().x, 0)))
            {
                ChangeMaxListArraySize(9999,
                                       [&object = currentObj]()
                                       {
                                           char fileName[256]{0};
                                           snprintf(fileName, sizeof(fileName), "dump_%s (%p).json",
                                                    object->klass->getName(), object);
                                           Util::FileWriter file(fileName);
                                           std::vector<uintptr_t> visited{};
                                           nlohmann::ordered_json j = object->dump(visited, 9999);
                                           file.write(j.dump(2, ' ').c_str());
                                           LOGD("Done save");
                                           ImGui::CloseCurrentPopup();
                                       });
            }
            ImGui::EndPopup();
        }
        poper.Update();
        ImGui::EndChild();
        ImGui::EndTable();
    }
}

void ClassesTab::FilterClasses(const std::string &filter)
{
    filteredClasses.clear();
    classes.clear();
    methodMap.clear(); // is this necessary?
    if (includeAllImages)
    {
        for (auto image : g_Images)
        {
            auto imageClasses = image->getClasses();
            classes.insert(classes.end(), imageClasses.begin(), imageClasses.end());
        }
    }
    else
    {
        classes = selectedImage->getClasses();
    }

    auto finderCaseSensitive = [](const std::string &a, const std::string &b)
    { return a.find(b) != std::string::npos; };

    auto finderCaseInsensitive = [](const std::string &a, const std::string &b)
    {
        auto newA = a;
        auto newB = b;
        std::transform(newA.begin(), newA.end(), newA.begin(), ::tolower);
        std::transform(newB.begin(), newB.end(), newB.begin(), ::tolower);
        return newA.find(newB) != std::string::npos;
    };

    auto finder = caseSensitive ? finderCaseSensitive : finderCaseInsensitive;

    for (int i = 0; i < classes.size() && filteredClasses.size() < (showAllClasses ? classes.size() : MAX_CLASSES); i++)
    {
        auto klass = classes[i];

        if (/* Il2cpp::GetClassIsStatic(klass) || */ Il2cpp::GetClassIsEnum(klass))
            continue;

        if (filterByClass)
        {
            // if (klass->getFullName().find(filter) != std::string::npos)
            if (finder(klass->getFullName(), filter))
            {
                filteredClasses.push_back(klass);
                for (auto m : klass->getMethods())
                {
                    auto paramsInfo = m->getParamsInfo();
                    methodMap[klass].push_back({m, paramsInfo});
                }
            }
        }
        else if (filterByMethod)
        {
            bool found = false;
            for (auto m : klass->getMethods())
            {
                // if (std::string(m->getName()).find(filter) != std::string::npos)
                if (finder(m->getName(), filter))
                {
                    found = true;
                    auto paramsInfo = m->getParamsInfo();
                    methodMap[klass].push_back({m, paramsInfo});
                }
            }
            if (found)
                filteredClasses.push_back(klass);
        }
        else if (filterByField)
        {
            bool found = false;
            for (auto f : klass->getFields())
            {
                // if (std::string(f->getName()).find(filter) != std::string::npos)
                if (finder(f->getName(), filter))
                {
                    found = true;
                }
            }
            if (found)
            {
                filteredClasses.push_back(klass);
                for (auto m : klass->getMethods())
                {
                    auto paramsInfo = m->getParamsInfo();
                    methodMap[klass].push_back({m, paramsInfo});
                }
            }
        }
    }
    Tool::ConfigSave();
}

void to_json(nlohmann::ordered_json &j, const ClassesTab &p)
{
    j["filter"] = p.filter;
    j["filterByClass"] = p.filterByClass;
    j["filterByField"] = p.filterByField;
    j["filterByMethod"] = p.filterByMethod;
    j["showAllClasses"] = p.showAllClasses;
    j["includeAllImages"] = p.includeAllImages;
    j["caseSensitive"] = p.caseSensitive;
    j["selectedImage"] = p.selectedImage->getName();
}

void from_json(const nlohmann::ordered_json &j, ClassesTab &p)
{
    j.at("filter").get_to(p.filter);
    j.at("filterByClass").get_to(p.filterByClass);
    j.at("filterByField").get_to(p.filterByField);
    j.at("filterByMethod").get_to(p.filterByMethod);
    j.at("showAllClasses").get_to(p.showAllClasses);
    j.at("includeAllImages").get_to(p.includeAllImages);
    j.at("caseSensitive").get_to(p.caseSensitive);
    std::string selectedImage = j.at("selectedImage").get<std::string>();
    if (selectedImage.size() >= 4 && selectedImage.compare(selectedImage.size() - 4, 4, ".dll") == 0) {
        selectedImage.erase(selectedImage.size() - 4);
    }
    auto assembly = Il2cpp::GetAssembly(selectedImage.c_str());
    if (assembly)
    {
        auto image = assembly->getImage();
        if (image)
        {
            p.selectedImage = image;
        }
    }
}

std::unordered_map<Il2CppClass *, std::vector<Il2CppObject *>> ClassesTab::objectMap;
std::unordered_map<Il2CppClass *, std::vector<Il2CppObject *>> ClassesTab::newObjectMap;
std::unordered_map<Il2CppClass *, std::set<Il2CppObject *>> ClassesTab::savedSet;
std::unordered_map<MethodInfo *, ClassesTab::OriginalMethodBytes> ClassesTab::oMap;
std::mutex ClassesTab::oMapMtx;
std::unordered_map<Il2CppClass *, bool> ClassesTab::states;
PopUpSelector ClassesTab::poper;
