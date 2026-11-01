# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.
# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)
project("nativelib")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(QBDI_ROOT ${CMAKE_SOURCE_DIR}/qbdi-arm64)

include_directories(
    # 项目头文件
    include hook raw_syscall third
    ${QBDI_ROOT}/include
)

macro(SET_OPTION option value)
    set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()

SET_OPTION(Plugin.LinkerLoadCallback ON)
SET_OPTION(Plugin.Android.BionicLinkerUtil ON)

# QBDI
add_library(qbdi-arm64 STATIC IMPORTED)
set_target_properties(qbdi-arm64 PROPERTIES IMPORTED_LOCATION ${QBDI_ROOT}/lib/libQBDI.a)

# ========================================================================================
# 源文件配置
# ========================================================================================
aux_source_directory(hook HOOK_SOURCES)
aux_source_directory(third THIRD_SOURCES)
set(PROJECT_SOURCES
    ${THIRD_SOURCES}
    native_main.cpp
    vm.cpp
    jnitrace.cpp
    libctrace.cpp
    qbdihook.cpp logger.cpp
    third/md5.c
    third/sds.c
    ${HOOK_SOURCES}
)

# ========================================================================================
# 目标库构建
# ========================================================================================
add_library(${CMAKE_PROJECT_NAME} SHARED ${PROJECT_SOURCES})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

# 链接库
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE
    # 主要框架
    qbdi-arm64
    # 系统库
    android log
)