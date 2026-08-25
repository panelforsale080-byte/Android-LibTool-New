#pragma once

namespace MenuLayout
{
    /** Pick a scale preset index (0–6) from the shorter screen side in px. */
    int RecommendedScaleIndex(float displayWidth, float displayHeight);

    /** Center the main menu and size it for phone screens (ignored when fullscreen). */
    void ApplyResponsiveMainWindow(bool fullScreen);

    /** Top-right FPS overlay; pass false to hide. */
    void DrawFpsOverlay();

    void SetFpsVisible(bool visible);
    bool IsFpsVisible();

    /** Call once per frame before the main menu is drawn. */
    void OnFrame(int displayWidth, int displayHeight);

    /** True after the first successful auto-scale pass. */
    bool AutoScaleApplied();

    void RequestAutoScale(int &selectedScale, bool &doChangeScale);

    /** Usable inner width of the current menu panel (phone-safe). */
    float ContentWidth();

    /** Scrollable list/table height as a fraction of remaining vertical space. */
    float ScrollPanelHeight(float heightRatio = 0.32f, float minPx = 120.f);

    /** True when the shorter display side is phone-sized. */
    bool IsNarrowLayout();
}
