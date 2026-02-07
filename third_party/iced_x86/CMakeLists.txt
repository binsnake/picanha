# third_party/iced_x86/CMakeLists.txt - iced_x86 library (NOT header-only)

# Collect source files (excluding disabled features)
set(ICED_X86_SOURCES
    ${PROJECT_SOURCE_DIR}/iced_x86/src/decoder.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/handlers.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/instruction.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/memory_size_info.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/mvex_info_data.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/op_code_info.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/register_info.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/table_deserializer.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/tables.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/fastfmt.cpp
    ${PROJECT_SOURCE_DIR}/iced_x86/src/instruction_info.cpp
)

# Add Intel formatter if enabled
if(NOT ICED_X86_NO_INTEL_FORMATTER)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/intel_formatter.cpp)
endif()

# Add other formatters if not disabled
if(NOT ICED_X86_NO_GAS_FORMATTER)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/gas_formatter.cpp)
endif()
if(NOT ICED_X86_NO_MASM_FORMATTER)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/masm_formatter.cpp)
endif()
if(NOT ICED_X86_NO_NASM_FORMATTER)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/nasm_formatter.cpp)
endif()

# Add encoder if not disabled
if(NOT ICED_X86_NO_ENCODER)
    list(APPEND ICED_X86_SOURCES
        ${PROJECT_SOURCE_DIR}/iced_x86/src/encoder.cpp
        ${PROJECT_SOURCE_DIR}/iced_x86/src/encoder_handlers.cpp
        ${PROJECT_SOURCE_DIR}/iced_x86/src/encoder_methods.cpp
        ${PROJECT_SOURCE_DIR}/iced_x86/src/encoder_ops.cpp
    )
endif()

# Add block encoder if not disabled
if(NOT ICED_X86_NO_BLOCK_ENCODER)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/block_encoder.cpp)
endif()

# Add instruction create if not disabled
if(NOT ICED_X86_NO_INSTRUCTION_CREATE)
    list(APPEND ICED_X86_SOURCES ${PROJECT_SOURCE_DIR}/iced_x86/src/instruction_create.cpp)
endif()

add_library(iced_x86 STATIC ${ICED_X86_SOURCES})

target_include_directories(iced_x86
    PUBLIC
        ${PROJECT_SOURCE_DIR}  # For #include <iced_x86/...>
)

# Configure iced_x86 features
target_compile_definitions(iced_x86
    PUBLIC
        # Disable encoder features
        $<$<BOOL:${ICED_X86_NO_ENCODER}>:ICED_X86_NO_ENCODER>
        $<$<BOOL:${ICED_X86_NO_BLOCK_ENCODER}>:ICED_X86_NO_BLOCK_ENCODER>
        $<$<BOOL:${ICED_X86_NO_INSTRUCTION_CREATE}>:ICED_X86_NO_INSTRUCTION_CREATE>

        # Disable unused formatters
        $<$<BOOL:${ICED_X86_NO_INTEL_FORMATTER}>:ICED_X86_NO_INTEL_FORMATTER>
        $<$<BOOL:${ICED_X86_NO_GAS_FORMATTER}>:ICED_X86_NO_GAS_FORMATTER>
        $<$<BOOL:${ICED_X86_NO_MASM_FORMATTER}>:ICED_X86_NO_MASM_FORMATTER>
        $<$<BOOL:${ICED_X86_NO_NASM_FORMATTER}>:ICED_X86_NO_NASM_FORMATTER>
)

# Set runtime library based on vcpkg triplet
if(WIN32)
    if(VCPKG_TARGET_TRIPLET MATCHES "static")
        set_property(TARGET iced_x86 PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set_property(TARGET iced_x86 PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

# Suppress warnings for third-party code
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(iced_x86 PRIVATE -w)
elseif(MSVC)
    target_compile_options(iced_x86 PRIVATE /W0)
endif()

# Add alias for consistency
add_library(iced::x86 ALIAS iced_x86)

message(STATUS "iced_x86 configured:")
message(STATUS "  Include: ${PROJECT_SOURCE_DIR}/iced_x86")
message(STATUS "  No Encoder: ${ICED_X86_NO_ENCODER}")
message(STATUS "  No Block Encoder: ${ICED_X86_NO_BLOCK_ENCODER}")
message(STATUS "  No Instruction Create: ${ICED_X86_NO_INSTRUCTION_CREATE}")
message(STATUS "  No Intel Formatter: ${ICED_X86_NO_INTEL_FORMATTER}")
message(STATUS "  No GAS Formatter: ${ICED_X86_NO_GAS_FORMATTER}")
message(STATUS "  No MASM Formatter: ${ICED_X86_NO_MASM_FORMATTER}")
message(STATUS "  No NASM Formatter: ${ICED_X86_NO_NASM_FORMATTER}")
