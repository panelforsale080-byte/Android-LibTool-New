LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := frida_gum
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libfrida-gum.a
include $(PREBUILT_STATIC_LIBRARY)
