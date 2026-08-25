LOCAL_PATH := $(call my-dir)
MY_ROOT_PATH := $(LOCAL_PATH)

include $(MY_ROOT_PATH)/asmjit/Android.mk
include $(MY_ROOT_PATH)/Dobby/Android.mk
include $(MY_ROOT_PATH)/Frida/Android.mk

LOCAL_PATH := $(MY_ROOT_PATH) # Reset for local path

include $(CLEAR_VARS)

LOCAL_MODULE := Tool

LOCAL_CFLAGS := -w -s -Wno-error=format-security -fvisibility=hidden -fpermissive -fexceptions

LOCAL_CPPFLAGS := -w -s -Wno-error=format-security \
    -fvisibility=hidden \
    -Werror \
    -std=c++17 \
    -Wno-error=c++11-narrowing \
    -fpermissive \
    -Wall \
    -fexceptions \
    -DUSE_FRIDA

LOCAL_LDFLAGS += -Wl,--gc-sections,--strip-all
LOCAL_LDLIBS := \
    -llog \
    -landroid \
    -lEGL \
    -lGLESv3 \
    -ldl \
    -latomic \
    -lz \
    -lm \
    -lc

LOCAL_ARM_MODE := arm

LOCAL_C_INCLUDES += $(MY_ROOT_PATH)
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/imgui
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/asmjit
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/Dobby
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/Dobby/include
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/Frida/gumpp
LOCAL_C_INCLUDES += $(MY_ROOT_PATH)/Frida/$(TARGET_ARCH_ABI)

LOCAL_STATIC_LIBRARIES := asmjit dobby frida_gum

LOCAL_SRC_FILES := \
    Main.cpp \
    Menu/ImGui.cpp \
    Menu/MenuLayout.cpp \
    Tool/Keyboard.cpp \
    Tool/ProcessTab.cpp \
    Tool/SoMonitor.cpp \
    Tool/SoMonitorTrace.cpp \
    Tool/Tool.cpp \
    Tool/Util.cpp \
    Tool/Patcher.cpp \
    Tool/PopUpSelector.cpp \
    Tool/ClassesTab.cpp \
    Tool/Unity.cpp \
    Tool/Frida.cpp \
    Includes/Utils.cpp \
    Includes/Logger.cpp \
    KittyMemory/KittyMemory.cpp \
    KittyMemory/MemoryPatch.cpp \
    KittyMemory/MemoryBackup.cpp \
    KittyMemory/KittyUtils.cpp \
    Il2cpp/Il2cpp.cpp \
    Il2cpp/il2cpp-class.cpp \
    Il2cpp/xdl/xdl.c \
    Il2cpp/xdl/xdl_iterate.c \
    Il2cpp/xdl/xdl_linker.c \
    Il2cpp/xdl/xdl_lzma.c \
    Il2cpp/xdl/xdl_util.c \
    imgui/imgui_widgets.cpp \
    imgui/imgui_draw.cpp \
    imgui/imgui_demo.cpp \
    imgui/imgui.cpp \
    imgui/imgui_tables.cpp \
    imgui/backends/imgui_impl_opengl3.cpp \
    imgui/backends/imgui_impl_android.cpp \
    Frida/gumpp/runtime.cpp \
    Frida/gumpp/backtracer.cpp \
    Frida/gumpp/interceptor.cpp \
    Frida/gumpp/invocationlistener.cpp \
    Frida/gumpp/returnaddress.cpp

include $(BUILD_SHARED_LIBRARY)
