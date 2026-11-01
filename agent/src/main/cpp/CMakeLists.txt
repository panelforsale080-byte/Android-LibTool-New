cmake_minimum_required(VERSION 3.18.1)
project(il2cpp_agent LANGUAGES C CXX)

set(JNI_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../app/src/main/jni")

add_library(il2cpp_agent SHARED
    agent.cpp
    "${JNI_ROOT}/Il2cpp/Il2cpp.cpp"
    "${JNI_ROOT}/Il2cpp/xdl/xdl.c"
    "${JNI_ROOT}/Il2cpp/xdl/xdl_iterate.c"
    "${JNI_ROOT}/Il2cpp/xdl/xdl_linker.c"
    "${JNI_ROOT}/Il2cpp/xdl/xdl_lzma.c"
    "${JNI_ROOT}/Il2cpp/xdl/xdl_util.c"
)

target_include_directories(il2cpp_agent PRIVATE
    "${JNI_ROOT}"
    "${JNI_ROOT}/Il2cpp"
    "${JNI_ROOT}/Il2cpp/xdl"
    "${JNI_ROOT}/Il2cpp/xdl/include"
    "${JNI_ROOT}/Includes"
)

target_compile_features(il2cpp_agent PRIVATE cxx_std_17)

set_target_properties(il2cpp_agent PROPERTIES
    OUTPUT_NAME "Tool"
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

target_compile_options(il2cpp_agent PRIVATE
    -fexceptions
    -fpermissive
    -fvisibility=hidden
    -ffunction-sections
    -fdata-sections
    -Wno-error
    -Wno-unused-parameter
)

target_compile_definitions(il2cpp_agent PRIVATE
    ANDROID
)

target_link_options(il2cpp_agent PRIVATE
    -Wl,--gc-sections
    -Wl,--strip-all
)

target_link_libraries(il2cpp_agent
    android
    log
    dl
)
