LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := dobby

LOCAL_CPPFLAGS += -std=c++11
LOCAL_CPPFLAGS += -fvisibility=hidden
LOCAL_CPPFLAGS += -fexceptions
LOCAL_CPPFLAGS += -w

LOCAL_CFLAGS += -fvisibility=hidden
LOCAL_CFLAGS += -fexceptions
LOCAL_CFLAGS += -w

# Debug / Release
ifeq ($(NDK_DEBUG),1)
    LOCAL_CPPFLAGS += -DDOBBY_DEBUG
else
    LOCAL_CPPFLAGS += -DDOBBY_LOGGING_DISABLE
endif

# Enable NearBranch
LOCAL_CPPFLAGS += -DNearBranch

LOCAL_C_INCLUDES += \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/source \
    $(LOCAL_PATH)/source/dobby \
    $(LOCAL_PATH)/source/Backend/UserMode \
    $(LOCAL_PATH)/external \
    $(LOCAL_PATH)/external/logging \
    $(LOCAL_PATH)/builtin-plugin \
    $(LOCAL_PATH)/builtin-plugin/SymbolResolver

LOCAL_SRC_FILES := \
    source/core/arch/CpuFeature.cc \
    source/core/arch/CpuRegister.cc \
    source/core/assembler/assembler.cc \
    source/core/assembler/assembler-arm.cc \
    source/core/assembler/assembler-arm64.cc \
    source/core/codegen/codegen-arm.cc \
    source/core/codegen/codegen-arm64.cc \
    source/MemoryAllocator/CodeBuffer/CodeBufferBase.cc \
    source/MemoryAllocator/AssemblyCodeBuilder.cc \
    source/MemoryAllocator/MemoryAllocator.cc \
    source/MemoryAllocator/NearMemoryAllocator.cc \
    source/InstructionRelocation/arm/InstructionRelocationARM.cc \
    source/InstructionRelocation/arm64/InstructionRelocationARM64.cc \
    source/InterceptRouting/InterceptRouting.cpp \
    source/InterceptRouting/RoutingPlugin/RoutingPlugin.cc \
    source/InterceptRouting/Routing/InstructionInstrument/InstructionInstrument.cc \
    source/InterceptRouting/Routing/InstructionInstrument/RoutingImpl.cc \
    source/InterceptRouting/Routing/InstructionInstrument/instrument_routing_handler.cc \
    source/InterceptRouting/Routing/FunctionInlineHook/FunctionInlineHook.cc \
    source/InterceptRouting/Routing/FunctionInlineHook/RoutingImpl.cc \
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc \
    source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc \
    source/TrampolineBridge/Trampoline/arm/trampoline_arm.cc \
    source/TrampolineBridge/Trampoline/arm64/trampoline_arm64.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/common_bridge_handler.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm/helper_arm.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm/closure_bridge_arm.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm/ClosureTrampolineARM.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm64/helper_arm64.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm64/closure_bridge_arm64.cc \
    source/TrampolineBridge/ClosureTrampolineBridge/arm64/ClosureTrampolineARM64.cc \
    source/Backend/UserMode/PlatformUtil/Linux/ProcessRuntimeUtility.cc \
    source/Backend/UserMode/UnifiedInterface/platform-posix.cc \
    source/Backend/UserMode/ExecMemory/code-patch-tool-posix.cc \
    source/Backend/UserMode/ExecMemory/clear-cache-tool-all.c \
    external/logging/logging.cc \
    source/dobby.cpp \
    source/Interceptor.cpp \
    source/InterceptEntry.cpp \
    builtin-plugin/SymbolResolver/elf/dobby_symbol_resolver.cc

LOCAL_ARM_MODE := arm

include $(BUILD_STATIC_LIBRARY)
