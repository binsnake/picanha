# CompilerFlags.cmake - Compiler-specific flags for LLVM/Clang and MSVC

include(CheckCXXCompilerFlag)

# Detect compiler
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(PICANHA_COMPILER_CLANG TRUE)
    if(MSVC)
        set(PICANHA_COMPILER_CLANG_CL TRUE)
    endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(PICANHA_COMPILER_MSVC TRUE)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(PICANHA_COMPILER_GCC TRUE)
endif()

# Common warning flags
function(picanha_set_warnings target)
    if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Wshadow
            -Wno-unused-parameter
            -Wno-missing-field-initializers
        )
    elseif(PICANHA_COMPILER_CLANG_CL)
        target_compile_options(${target} PRIVATE
            /W4
            -Wno-unused-parameter
            -Wno-missing-field-initializers
        )
    elseif(PICANHA_COMPILER_MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            /wd4100  # unreferenced formal parameter
            /wd4201  # nameless struct/union
            /wd4324  # structure padding
        )
    endif()
endfunction()

# Optimization flags
function(picanha_set_optimization target)
    if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Debug>:-O0 -g>
            $<$<CONFIG:Release>:-O3 -DNDEBUG>
            $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
        )
    elseif(PICANHA_COMPILER_CLANG_CL OR PICANHA_COMPILER_MSVC)
        target_compile_options(${target} PRIVATE
            $<$<CONFIG:Debug>:/Od /Zi>
            $<$<CONFIG:Release>:/O2 /DNDEBUG>
            $<$<CONFIG:RelWithDebInfo>:/O2 /Zi /DNDEBUG>
        )
    endif()
endfunction()

# Link-time optimization
function(picanha_enable_lto target)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
            target_compile_options(${target} PRIVATE -flto=thin)
            target_link_options(${target} PRIVATE -flto=thin)
        elseif(PICANHA_COMPILER_MSVC)
            target_compile_options(${target} PRIVATE /GL)
            target_link_options(${target} PRIVATE /LTCG)
        endif()
    endif()
endfunction()

# Sanitizers (Debug builds)
option(PICANHA_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(PICANHA_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

function(picanha_enable_sanitizers target)
    if(PICANHA_ENABLE_ASAN)
        if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
            target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address)
        elseif(PICANHA_COMPILER_MSVC)
            target_compile_options(${target} PRIVATE /fsanitize=address)
        endif()
    endif()

    if(PICANHA_ENABLE_UBSAN)
        if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
            target_compile_options(${target} PRIVATE -fsanitize=undefined)
            target_link_options(${target} PRIVATE -fsanitize=undefined)
        endif()
    endif()
endfunction()

# Apply all standard flags to a target
function(picanha_configure_target target)
    picanha_set_warnings(${target})
    picanha_set_optimization(${target})
    picanha_enable_sanitizers(${target})

    # Windows-specific
    if(WIN32)
        target_compile_definitions(${target} PRIVATE
            _CRT_SECURE_NO_WARNINGS
            NOMINMAX
            WIN32_LEAN_AND_MEAN
        )
        # Use appropriate runtime library based on vcpkg triplet
        # Static triplet (x64-windows-static): MT
        # Dynamic triplet (x64-windows): MD
        if(PICANHA_COMPILER_CLANG_CL OR PICANHA_COMPILER_MSVC)
            if(VCPKG_TARGET_TRIPLET MATCHES "static")
                set_property(TARGET ${target} PROPERTY
                    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
            else()
                set_property(TARGET ${target} PROPERTY
                    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
            endif()
        elseif(PICANHA_COMPILER_CLANG)
            # Clang with GNU-like command line on Windows
            if(VCPKG_TARGET_TRIPLET MATCHES "static")
                target_compile_options(${target} PRIVATE
                    $<$<CONFIG:Debug>:-D_MT -D_DEBUG -Xclang --dependent-lib=libcmtd>
                    $<$<CONFIG:Release>:-D_MT -DNDEBUG -Xclang --dependent-lib=libcmt>
                    $<$<CONFIG:RelWithDebInfo>:-D_MT -DNDEBUG -Xclang --dependent-lib=libcmt>
                )
            else()
                target_compile_options(${target} PRIVATE
                    $<$<CONFIG:Debug>:-D_MT -D_DEBUG -Xclang --dependent-lib=msvcrtd>
                    $<$<CONFIG:Release>:-D_MT -DNDEBUG -Xclang --dependent-lib=msvcrt>
                    $<$<CONFIG:RelWithDebInfo>:-D_MT -DNDEBUG -Xclang --dependent-lib=msvcrt>
                )
            endif()
        endif()
    endif()

    # Use spdlog with std::format to avoid fmt consteval issues with Clang
    if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_CLANG_CL)
        target_compile_definitions(${target} PRIVATE
            SPDLOG_USE_STD_FORMAT=1
            SPDLOG_HEADER_ONLY=1
        )
    endif()
endfunction()

# SIMD flags
function(picanha_enable_simd target)
    if(PICANHA_COMPILER_CLANG OR PICANHA_COMPILER_GCC)
        check_cxx_compiler_flag("-mavx2" COMPILER_HAS_AVX2)
        if(COMPILER_HAS_AVX2)
            target_compile_options(${target} PRIVATE -mavx2)
        endif()
    elseif(PICANHA_COMPILER_MSVC)
        target_compile_options(${target} PRIVATE /arch:AVX2)
    endif()
endfunction()
