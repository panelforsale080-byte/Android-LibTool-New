#include "ImGui.h"
#include "Menu/MenuLayout.h"
#include "KittyMemory/KittyMemory.h"
#include "Dobby/include/dobby.h"
#include "Includes/Utils.h"
#include "Includes/obfuscate.h"
#include "Includes/Logger.h"
#include "imgui/imgui.h"
#include "Includes/Roboto-Regular.h"
#include "imgui/backends/imgui_impl_opengl3.h"
#include "imgui/backends/imgui_impl_android.h"
#include "Il2cpp/Il2cpp.h"
#include <GLES3/gl3.h>
#include <string>
#include <unistd.h>
#include <algorithm>
#include "EGL/egl.h"

using swapbuffers_orig = EGLBoolean (*)(EGLDisplay dpy, EGLSurface surf);
EGLBoolean swapbuffers_hook(EGLDisplay dpy, EGLSurface surf);
swapbuffers_orig o_swapbuffers = nullptr;

extern JavaVM *g_vm;

static void SetClipboardText(void *user_data, const char *text)
{
    // Try Unity GUIUtility first
    auto GUIUtility = Il2cpp::FindClass("UnityEngine.GUIUtility");
    if (GUIUtility)
    {
        auto set_systemCopyBuffer = GUIUtility->getMethod("set_systemCopyBuffer", 1);
        if (set_systemCopyBuffer)
        {
            set_systemCopyBuffer->invoke_static<void>(Il2cpp::NewString(text));
            LOGD("Clipboard set via Unity GUIUtility");
            return;
        }
    }

    // Fallback to Android JNI
    if (g_vm)
    {
        JNIEnv *env = nullptr;
        bool attached = false;
        if (g_vm->GetEnv((void **)&env, JNI_VERSION_1_6) == JNI_EDETACHED)
        {
            if (g_vm->AttachCurrentThread(&env, nullptr) == JNI_OK)
            {
                attached = true;
            }
        }

        if (env)
        {
            jclass unityPlayer = env->FindClass("com/unity3d/player/UnityPlayer");
            if (unityPlayer)
            {
                jfieldID currentActivityField = env->GetStaticFieldID(unityPlayer, "currentActivity", "Landroid/app/Activity;");
                jobject activity = env->GetStaticObjectField(unityPlayer, currentActivityField);
                if (activity)
                {
                    jclass activityClass = env->GetObjectClass(activity);
                    jmethodID getSystemService = env->GetMethodID(activityClass, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
                    jstring serviceName = env->NewStringUTF("clipboard");
                    jobject clipboardManager = env->CallObjectMethod(activity, getSystemService, serviceName);

                    if (clipboardManager)
                    {
                        jclass clipDataClass = env->FindClass("android/content/ClipData");
                        jmethodID newPlainText = env->GetStaticMethodID(clipDataClass, "newPlainText", "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;");
                        jstring label = env->NewStringUTF("ImGui Clipboard");
                        jstring textStr = env->NewStringUTF(text);
                        jobject clipData = env->CallStaticObjectMethod(clipDataClass, newPlainText, label, textStr);

                        jclass clipboardManagerClass = env->GetObjectClass(clipboardManager);
                        jmethodID setPrimaryClip = env->GetMethodID(clipboardManagerClass, "setPrimaryClip", "(Landroid/content/ClipData;)V");
                        env->CallVoidMethod(clipboardManager, setPrimaryClip, clipData);
                        LOGD("Clipboard set via Android JNI");
                    }
                }
            }

            if (attached)
                g_vm->DetachCurrentThread();
        }
    }
}

static const char *GetClipboardText(void *user_data)
{
    static std::string clipboard;
    auto GUIUtility = Il2cpp::FindClass("UnityEngine.GUIUtility");
    if (GUIUtility)
    {
        auto str = GUIUtility->invoke_static_method<Il2CppString *>("get_systemCopyBuffer");
        if (str)
        {
            clipboard = str->to_string();
            return clipboard.c_str();
        }
    }
    return nullptr;
}

void (*menuAddress)();
void (*onInitAddr)();

bool isInitialized = false;
int glWidth = 0;
int glHeight = 0;

int getGlWidth()
{
    return glWidth;
}
int getGlHeight()
{
    return glHeight;
}

// Taken from https://github.com/fedes1to/Zygisk-ImGui-Menu/blob/main/module/src/main/cpp/hook.cpp
#define HOOKINPUT(ret, func, ...)                                                                                      \
    ret (*orig##func)(__VA_ARGS__);                                                                                    \
    ret my##func(__VA_ARGS__)

HOOKINPUT(void, Input, void *thiz, void *ex_ab, void *ex_ac)
{
    origInput(thiz, ex_ab, ex_ac);
    if (isInitialized)
        ImGui_ImplAndroid_HandleInputEvent((AInputEvent *)thiz);
    return;
}

ANativeWindow* g_AppWindow = nullptr;
void setNativeWindow(ANativeWindow* window) {
    g_AppWindow = window;
}

ImVec2 initialScreenSize;
// This menu_addr is used to allow for multiple game support in the future
bool needClear = true;
void *initModMenu(void *menu_addr, void *on_init_addr, bool isJni)
{
    menuAddress = (void (*)())menu_addr;
    onInitAddr = (void (*)())on_init_addr;
    // do
    // {
    //     sleep(1);
    // } while (!isLibraryLoaded(OBFUSCATE("libEGL.so")));
    if (!isJni)
    {
        needClear = false;
        while (!isLibraryLoaded(OBFUSCATE("libEGL.so")))
        {
            sleep(1);
        }
        auto swapBuffers = ((uintptr_t)DobbySymbolResolver(OBFUSCATE("libEGL.so"), OBFUSCATE("eglSwapBuffers")));
        KittyMemory::ProtectAddr((void *)swapBuffers, sizeof(swapBuffers), PROT_READ | PROT_WRITE | PROT_EXEC);
        DobbyHook((void *)swapBuffers, (void *)swapbuffers_hook, (void **)&o_swapbuffers);

// // Taken from https://github.com/fedes1to/Zygisk-ImGui-Menu/blob/main/module/src/main/cpp/hook.cpp
#ifdef LIB_INPUT
        void *sym_input = DobbySymbolResolver(
            OBFUSCATE("/system/lib/libinput.so"),
            OBFUSCATE("_ZN7android13InputConsumer21initializeMotionEventEPNS_11MotionEventEPKNS_12InputMessageE"));
        if (sym_input != nullptr)
        {
            DobbyHook((void *)sym_input, (void *)myInput, (void **)&origInput);
        }
#endif
    }
    LOGI("%s", (char *)OBFUSCATE("ImGUI Hooks initialized"));
    return nullptr;
}

void setupMenu()
{
    if (isInitialized)
        return;

    auto ctx = ImGui::CreateContext();
    if (!ctx)
    {
        LOGI("%s", (char *)OBFUSCATE("Failed to create context"));
        return;
    }

    ImGuiIO &io = ImGui::GetIO();
    io.DisplaySize = ImVec2((float)glWidth, (float)glHeight);
    // io.ConfigWindowsMoveFromTitleBarOnly = true;
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    io.SetClipboardTextFn = SetClipboardText;
    io.GetClipboardTextFn = GetClipboardText;

    // Setup Platform/Renderer backends
    ImGui_ImplAndroid_Init(g_AppWindow);
    ImGui_ImplOpenGL3_Init("#version 300 es");

    const float shortSide = (glWidth > 0 && glHeight > 0)
                                ? (float)std::min(glWidth, glHeight)
                                : 720.f;
    const float fontPx = std::max(18.f, std::min(shortSide * 0.028f, 26.f));
    const float uiScale = std::max(0.85f, std::min(shortSide / 720.f, 1.25f));
    io.Fonts->AddFontFromMemoryTTF(Roboto_Regular, sizeof(Roboto_Regular), fontPx);

    ImGui::GetStyle().ScaleAllSizes(uiScale);
    ImGuiStyle &style = ImGui::GetStyle();
    style.ScrollbarSize = std::max(style.ScrollbarSize, 14.f);
    style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
    style.TouchExtraPadding = ImVec2(4.f, 4.f);

    if (onInitAddr)
        onInitAddr();

    isInitialized = true;
    LOGI("setup done.");
}

void handleInputEvent(int action, float x, float y)
{
    if (!isInitialized)
        return;

    ImGuiIO &io = ImGui::GetIO();

    // Smooth scrolling and touch handling
    ImVec2 currentScreenSize = io.DisplaySize;
    float scaleX = currentScreenSize.x / initialScreenSize.x;
    float scaleY = currentScreenSize.y / initialScreenSize.y;
    float scaledX = x * scaleX;
    float scaledY = y * scaleY;

    // action == 0: down, 1: up, 2: move
    if (action == 0) // AMOTION_EVENT_ACTION_DOWN
    {
        io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
        io.AddMousePosEvent(scaledX, scaledY);
        io.AddMouseButtonEvent(0, true);
    }
    else if (action == 1) // AMOTION_EVENT_ACTION_UP
    {
        io.AddMousePosEvent(scaledX, scaledY);
        io.AddMouseButtonEvent(0, false);
    }
    else if (action == 2) // AMOTION_EVENT_ACTION_MOVE
    {
        io.AddMousePosEvent(scaledX, scaledY);
    }
}
void internalDrawMenu(int width, int height)
{
    if (!isInitialized)
        return;

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame(width, height);
    ImGui::NewFrame();

    MenuLayout::OnFrame(width, height);
    MenuLayout::DrawFpsOverlay();
    menuAddress();

    ImGui::Render();

    if (needClear)
    {
        glViewport(0, 0, width, height);
        glClearColor(0.0f, 0.0f, 0.0f, 0.0f);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

EGLBoolean swapbuffers_hook(EGLDisplay dpy, EGLSurface surf)
{
    EGLint w, h;
    eglQuerySurface(dpy, surf, EGL_WIDTH, &w);
    eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
    glWidth = w;
    glHeight = h;
    static bool initialScreenSet = false;
    if (!initialScreenSet)
    {
        initialScreenSize.x = w;
        initialScreenSize.y = h;
        initialScreenSet = true;
    }
    setupMenu();
    internalDrawMenu(w, h);

    return o_swapbuffers(dpy, surf);
}
