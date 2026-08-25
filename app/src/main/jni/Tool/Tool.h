#pragma once
#include "Il2cpp/il2cpp-class.h"
#include "Includes/circular_buffer.h"
#include "Tool/ClassesTab.h"
#include <set>

struct HookerTrace
{
    std::string name;
    float time;
    float goneTime;
    int hitCount;
};

struct HookerData
{
    int hitCount = 0;
    float time = 0.f;
    MethodInfo *method = nullptr;
    bool backtracing = false;
    bool silent = false;
    CircularBuffer<std::vector<std::string>> backtraced{10};
    static CircularBuffer<HookerTrace> visited;
    static std::unordered_map<Il2CppClass *, std::set<Il2CppObject *>> collectSet;
};
namespace Tool
{
    void ConfigSave();
    void ConfigLoad();
    void Init(Il2CppImage *image, std::vector<Il2CppImage *> images);
    void FilterClasses(const std::string &filter);
    void Draw();
    void Tracer();
    void Hooker();
    void GameObjects();
    void Strings();
    void Dumper();
    bool ToggleHooker(MethodInfo *method, int state = -1, bool silent = false);
    void CalculateSomething();
    ClassesTab &GetFirstTab(); // TODO: maybe just return classesTabs
    ClassesTab &OpenNewTab();
    ClassesTab &OpenNewTabFromClass(Il2CppClass *klass);
    std::string GetWindowRect();
    void AddNotification(const std::string &title, const std::string &message, bool success = true,
                         float duration = 3.0f);
    void DrawNotifications();
} // namespace Tool
