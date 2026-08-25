#include "MenuLayout.h"
#include "imgui/imgui.h"
#include <algorithm>
#include <cmath>
#include <cstdio>

namespace
{
    bool g_autoScaleApplied = false;
    bool g_windowSized = false;
    bool g_showFps = true;
    int g_lastW = 0;
    int g_lastH = 0;

    float Clamp(float v, float lo, float hi)
    {
        return std::max(lo, std::min(v, hi));
    }
}

namespace MenuLayout
{

int RecommendedScaleIndex(float displayWidth, float displayHeight)
{
    const float shortSide = std::min(displayWidth, displayHeight);
    if (shortSide <= 0.f)
        return 3;

    // Phone-first presets — smaller screens get tighter UI automatically.
    if (shortSide < 480.f)
        return 0; // Tiny
    if (shortSide < 600.f)
        return 1; // Compact
    if (shortSide < 720.f)
        return 2; // Small
    if (shortSide < 900.f)
        return 3; // Normal
    if (shortSide < 1080.f)
        return 4; // Medium
    if (shortSide < 1280.f)
        return 5; // Large
    return 6;     // XL
}

void ApplyResponsiveMainWindow(bool fullScreen)
{
    if (fullScreen)
        return;

    ImGuiIO &io = ImGui::GetIO();
    const ImVec2 display = io.DisplaySize;
    if (display.x < 32.f || display.y < 32.f)
        return;

    const float shortSide = std::min(display.x, display.y);
    const float widthRatio = shortSide < 720.f ? 0.96f : 0.92f;
    const float heightRatio = shortSide < 720.f ? 0.90f : 0.86f;

    float menuW = display.x * widthRatio;
    float menuH = display.y * heightRatio;
    menuW = Clamp(menuW, 280.f, display.x);
    menuH = Clamp(menuH, 340.f, display.y);

    const float posX = (display.x - menuW) * 0.5f;
    const float posY = Clamp(display.y * 0.04f, 8.f, display.y * 0.08f);

    ImGui::SetNextWindowPos(ImVec2(posX, posY), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(menuW, menuH), ImGuiCond_Always);
}

void DrawFpsOverlay()
{
    if (!g_showFps)
        return;

    ImGuiIO &io = ImGui::GetIO();
    if (io.DisplaySize.x < 1.f || io.DisplaySize.y < 1.f)
        return;

    const float fps = io.Framerate > 0.f ? io.Framerate : (io.DeltaTime > 0.f ? 1.f / io.DeltaTime : 0.f);
    char label[48];
    std::snprintf(label, sizeof(label), "FPS %.0f", fps);

    const ImVec2 textSize = ImGui::CalcTextSize(label);
    const float padX = 8.f;
    const float padY = 5.f;
    const ImVec2 pos(io.DisplaySize.x - textSize.x - padX * 2.f - 10.f, 10.f);
    const ImVec2 p0(pos.x - padX, pos.y - padY);
    const ImVec2 p1(pos.x + textSize.x + padX, pos.y + textSize.y + padY);

    ImDrawList *fg = ImGui::GetForegroundDrawList();
    fg->AddRectFilled(p0, p1, IM_COL32(8, 12, 18, 170), 6.f);
    fg->AddRect(p0, p1, IM_COL32(40, 170, 240, 180), 6.f);
    fg->AddText(pos, IM_COL32(180, 230, 255, 255), label);
}

void OnFrame(int displayWidth, int displayHeight)
{
    if (displayWidth <= 0 || displayHeight <= 0)
        return;

    if (displayWidth != g_lastW || displayHeight != g_lastH)
    {
        g_lastW = displayWidth;
        g_lastH = displayHeight;
        g_windowSized = false;
    }
}

bool AutoScaleApplied()
{
    return g_autoScaleApplied;
}

void RequestAutoScale(int &selectedScale, bool &doChangeScale)
{
    if (g_autoScaleApplied)
        return;

    ImGuiIO &io = ImGui::GetIO();
    if (io.DisplaySize.x < 32.f || io.DisplaySize.y < 32.f)
        return;

    g_autoScaleApplied = true;
    const int recommended = RecommendedScaleIndex(io.DisplaySize.x, io.DisplaySize.y);
    if (selectedScale != recommended)
    {
        selectedScale = recommended;
        doChangeScale = true;
    }
}

void SetFpsVisible(bool visible)
{
    g_showFps = visible;
}

bool IsFpsVisible()
{
    return g_showFps;
}

float ContentWidth()
{
    const float w = ImGui::GetContentRegionAvail().x;
    return w > 8.f ? w : ImGui::GetIO().DisplaySize.x * 0.9f;
}

float ScrollPanelHeight(float heightRatio, float minPx)
{
    const float h = ImGui::GetContentRegionAvail().y * heightRatio;
    return std::max(minPx, h);
}

bool IsNarrowLayout()
{
    const ImVec2 d = ImGui::GetIO().DisplaySize;
    return std::min(d.x, d.y) < 720.f;
}

} // namespace MenuLayout
