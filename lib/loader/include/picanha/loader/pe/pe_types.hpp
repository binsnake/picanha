#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/bitflags.hpp>
#include <cstdint>
#include <array>
#include <string_view>

namespace picanha::loader::pe {

// DOS header magic
inline constexpr std::uint16_t DOS_SIGNATURE = 0x5A4D;  // "MZ"

// PE signature
inline constexpr std::uint32_t PE_SIGNATURE = 0x00004550;  // "PE\0\0"

// Machine types
enum class MachineType : std::uint16_t {
    Unknown   = 0x0000,
    I386      = 0x014C,
    AMD64     = 0x8664,
    ARM       = 0x01C0,
    ARM64     = 0xAA64,
    ARMNT     = 0x01C4,
    IA64      = 0x0200,
};

// PE magic numbers for optional header
enum class PEMagic : std::uint16_t {
    PE32      = 0x10B,
    PE32Plus  = 0x20B,  // PE32+ (64-bit)
    ROM       = 0x107,
};

// Subsystem
enum class Subsystem : std::uint16_t {
    Unknown                  = 0,
    Native                   = 1,
    WindowsGui               = 2,
    WindowsCui               = 3,
    Os2Cui                   = 5,
    PosixCui                 = 7,
    NativeWindows            = 8,
    WindowsCEGui             = 9,
    EfiApplication           = 10,
    EfiBootServiceDriver     = 11,
    EfiRuntimeDriver         = 12,
    EfiRom                   = 13,
    Xbox                     = 14,
    WindowsBootApplication   = 16,
};

// DLL characteristics flags
enum class DllCharacteristics : std::uint16_t {
    None                     = 0,
    HighEntropyVA            = 0x0020,
    DynamicBase              = 0x0040,
    ForceIntegrity           = 0x0080,
    NxCompat                 = 0x0100,
    NoIsolation              = 0x0200,
    NoSEH                    = 0x0400,
    NoBind                   = 0x0800,
    AppContainer             = 0x1000,
    WdmDriver                = 0x2000,
    GuardCF                  = 0x4000,
    TerminalServerAware      = 0x8000,
};
PICANHA_ENABLE_BITFLAGS(DllCharacteristics);

// Section characteristics
enum class SectionFlags : std::uint32_t {
    None                     = 0,
    TypeNoPad                = 0x00000008,
    CntCode                  = 0x00000020,
    CntInitializedData       = 0x00000040,
    CntUninitializedData     = 0x00000080,
    LnkOther                 = 0x00000100,
    LnkInfo                  = 0x00000200,
    LnkRemove                = 0x00000800,
    LnkComdat                = 0x00001000,
    GpRel                    = 0x00008000,
    MemPurgeable             = 0x00020000,
    MemLocked                = 0x00040000,
    MemPreload               = 0x00080000,
    Align1Bytes              = 0x00100000,
    Align2Bytes              = 0x00200000,
    Align4Bytes              = 0x00300000,
    Align8Bytes              = 0x00400000,
    Align16Bytes             = 0x00500000,
    Align32Bytes             = 0x00600000,
    Align64Bytes             = 0x00700000,
    Align128Bytes            = 0x00800000,
    Align256Bytes            = 0x00900000,
    Align512Bytes            = 0x00A00000,
    Align1024Bytes           = 0x00B00000,
    Align2048Bytes           = 0x00C00000,
    Align4096Bytes           = 0x00D00000,
    Align8192Bytes           = 0x00E00000,
    LnkNRelocOvfl            = 0x01000000,
    MemDiscardable           = 0x02000000,
    MemNotCached             = 0x04000000,
    MemNotPaged              = 0x08000000,
    MemShared                = 0x10000000,
    MemExecute               = 0x20000000,
    MemRead                  = 0x40000000,
    MemWrite                 = 0x80000000,
};
PICANHA_ENABLE_BITFLAGS(SectionFlags);

// File characteristics (COFF header flags)
enum class FileCharacteristics : std::uint16_t {
    None                     = 0,
    RelocsStripped           = 0x0001,
    ExecutableImage          = 0x0002,
    LineNumsStripped         = 0x0004,
    LocalSymsStripped        = 0x0008,
    AggressiveWsTrim         = 0x0010,
    LargeAddressAware        = 0x0020,
    BytesReversedLo          = 0x0080,
    Machine32Bit             = 0x0100,
    DebugStripped            = 0x0200,
    RemovableRunFromSwap     = 0x0400,
    NetRunFromSwap           = 0x0800,
    System                   = 0x1000,
    Dll                      = 0x2000,
    UpSystemOnly             = 0x4000,
    BytesReversedHi          = 0x8000,
};
PICANHA_ENABLE_BITFLAGS(FileCharacteristics);

// Data directory indices
enum class DataDirectoryIndex : std::size_t {
    Export          = 0,
    Import          = 1,
    Resource        = 2,
    Exception       = 3,
    Security        = 4,
    BaseReloc       = 5,
    Debug           = 6,
    Architecture    = 7,
    GlobalPtr       = 8,
    TLS             = 9,
    LoadConfig      = 10,
    BoundImport     = 11,
    IAT             = 12,
    DelayImport     = 13,
    CLRRuntime      = 14,
    Reserved        = 15,
    Count           = 16,
};

// DOS Header (64 bytes)
struct DosHeader {
    std::uint16_t e_magic;      // Magic number (MZ)
    std::uint16_t e_cblp;       // Bytes on last page
    std::uint16_t e_cp;         // Pages in file
    std::uint16_t e_crlc;       // Relocations
    std::uint16_t e_cparhdr;    // Size of header in paragraphs
    std::uint16_t e_minalloc;   // Minimum extra paragraphs
    std::uint16_t e_maxalloc;   // Maximum extra paragraphs
    std::uint16_t e_ss;         // Initial SS value
    std::uint16_t e_sp;         // Initial SP value
    std::uint16_t e_csum;       // Checksum
    std::uint16_t e_ip;         // Initial IP value
    std::uint16_t e_cs;         // Initial CS value
    std::uint16_t e_lfarlc;     // File address of relocation table
    std::uint16_t e_ovno;       // Overlay number
    std::uint16_t e_res[4];     // Reserved
    std::uint16_t e_oemid;      // OEM identifier
    std::uint16_t e_oeminfo;    // OEM information
    std::uint16_t e_res2[10];   // Reserved
    std::int32_t  e_lfanew;     // File address of PE header
};
static_assert(sizeof(DosHeader) == 64);

// COFF File Header (20 bytes)
struct CoffHeader {
    MachineType         Machine;
    std::uint16_t       NumberOfSections;
    std::uint32_t       TimeDateStamp;
    std::uint32_t       PointerToSymbolTable;
    std::uint32_t       NumberOfSymbols;
    std::uint16_t       SizeOfOptionalHeader;
    FileCharacteristics Characteristics;
};
static_assert(sizeof(CoffHeader) == 20);

// Data Directory (8 bytes)
struct DataDirectory {
    std::uint32_t VirtualAddress;
    std::uint32_t Size;

    [[nodiscard]] bool is_present() const noexcept {
        return VirtualAddress != 0 && Size != 0;
    }
};
static_assert(sizeof(DataDirectory) == 8);

// Optional Header PE32 (96 bytes standard fields + data directories)
struct OptionalHeader32 {
    // Standard fields
    PEMagic             Magic;
    std::uint8_t        MajorLinkerVersion;
    std::uint8_t        MinorLinkerVersion;
    std::uint32_t       SizeOfCode;
    std::uint32_t       SizeOfInitializedData;
    std::uint32_t       SizeOfUninitializedData;
    std::uint32_t       AddressOfEntryPoint;
    std::uint32_t       BaseOfCode;
    std::uint32_t       BaseOfData;

    // Windows-specific fields
    std::uint32_t       ImageBase;
    std::uint32_t       SectionAlignment;
    std::uint32_t       FileAlignment;
    std::uint16_t       MajorOperatingSystemVersion;
    std::uint16_t       MinorOperatingSystemVersion;
    std::uint16_t       MajorImageVersion;
    std::uint16_t       MinorImageVersion;
    std::uint16_t       MajorSubsystemVersion;
    std::uint16_t       MinorSubsystemVersion;
    std::uint32_t       Win32VersionValue;
    std::uint32_t       SizeOfImage;
    std::uint32_t       SizeOfHeaders;
    std::uint32_t       CheckSum;
    Subsystem           Subsystem_;
    DllCharacteristics  DllCharacteristics_;
    std::uint32_t       SizeOfStackReserve;
    std::uint32_t       SizeOfStackCommit;
    std::uint32_t       SizeOfHeapReserve;
    std::uint32_t       SizeOfHeapCommit;
    std::uint32_t       LoaderFlags;
    std::uint32_t       NumberOfRvaAndSizes;

    // Data directories follow (variable length based on NumberOfRvaAndSizes)
};

// Optional Header PE32+ (112 bytes standard fields + data directories)
struct OptionalHeader64 {
    // Standard fields
    PEMagic             Magic;
    std::uint8_t        MajorLinkerVersion;
    std::uint8_t        MinorLinkerVersion;
    std::uint32_t       SizeOfCode;
    std::uint32_t       SizeOfInitializedData;
    std::uint32_t       SizeOfUninitializedData;
    std::uint32_t       AddressOfEntryPoint;
    std::uint32_t       BaseOfCode;

    // Windows-specific fields (note: no BaseOfData in PE32+)
    std::uint64_t       ImageBase;
    std::uint32_t       SectionAlignment;
    std::uint32_t       FileAlignment;
    std::uint16_t       MajorOperatingSystemVersion;
    std::uint16_t       MinorOperatingSystemVersion;
    std::uint16_t       MajorImageVersion;
    std::uint16_t       MinorImageVersion;
    std::uint16_t       MajorSubsystemVersion;
    std::uint16_t       MinorSubsystemVersion;
    std::uint32_t       Win32VersionValue;
    std::uint32_t       SizeOfImage;
    std::uint32_t       SizeOfHeaders;
    std::uint32_t       CheckSum;
    Subsystem           Subsystem_;
    DllCharacteristics  DllCharacteristics_;
    std::uint64_t       SizeOfStackReserve;
    std::uint64_t       SizeOfStackCommit;
    std::uint64_t       SizeOfHeapReserve;
    std::uint64_t       SizeOfHeapCommit;
    std::uint32_t       LoaderFlags;
    std::uint32_t       NumberOfRvaAndSizes;

    // Data directories follow (variable length based on NumberOfRvaAndSizes)
};

// Section Header (40 bytes)
struct SectionHeader {
    std::array<char, 8> Name;
    std::uint32_t       VirtualSize;
    std::uint32_t       VirtualAddress;
    std::uint32_t       SizeOfRawData;
    std::uint32_t       PointerToRawData;
    std::uint32_t       PointerToRelocations;
    std::uint32_t       PointerToLinenumbers;
    std::uint16_t       NumberOfRelocations;
    std::uint16_t       NumberOfLinenumbers;
    SectionFlags        Characteristics;

    [[nodiscard]] std::string_view name() const noexcept {
        // Find null terminator or use full 8 chars
        std::size_t len = 0;
        while (len < 8 && Name[len] != '\0') ++len;
        return std::string_view(Name.data(), len);
    }

    [[nodiscard]] bool is_executable() const noexcept {
        return has_flag(Characteristics, SectionFlags::MemExecute);
    }

    [[nodiscard]] bool is_writable() const noexcept {
        return has_flag(Characteristics, SectionFlags::MemWrite);
    }

    [[nodiscard]] bool is_readable() const noexcept {
        return has_flag(Characteristics, SectionFlags::MemRead);
    }

    [[nodiscard]] bool contains_code() const noexcept {
        return has_flag(Characteristics, SectionFlags::CntCode);
    }

    [[nodiscard]] bool contains_initialized_data() const noexcept {
        return has_flag(Characteristics, SectionFlags::CntInitializedData);
    }

    [[nodiscard]] bool contains_uninitialized_data() const noexcept {
        return has_flag(Characteristics, SectionFlags::CntUninitializedData);
    }
};
static_assert(sizeof(SectionHeader) == 40);

// Export Directory
struct ExportDirectory {
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;                 // RVA to DLL name
    std::uint32_t Base;                 // Ordinal base
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;   // RVA to function addresses
    std::uint32_t AddressOfNames;       // RVA to name pointers
    std::uint32_t AddressOfNameOrdinals; // RVA to ordinals
};
static_assert(sizeof(ExportDirectory) == 40);

// Import Directory Entry
struct ImportDescriptor {
    std::uint32_t OriginalFirstThunk;   // RVA to INT (Import Name Table)
    std::uint32_t TimeDateStamp;
    std::uint32_t ForwarderChain;
    std::uint32_t Name;                 // RVA to DLL name
    std::uint32_t FirstThunk;           // RVA to IAT (Import Address Table)

    [[nodiscard]] bool is_null() const noexcept {
        return OriginalFirstThunk == 0 && Name == 0 && FirstThunk == 0;
    }
};
static_assert(sizeof(ImportDescriptor) == 20);

// Import by Name
struct ImportByName {
    std::uint16_t Hint;
    // Name follows as null-terminated string
};

// Base Relocation Block
struct BaseRelocationBlock {
    std::uint32_t VirtualAddress;
    std::uint32_t SizeOfBlock;
    // Entries follow as array of uint16_t
};

// Base Relocation Entry (packed into uint16_t)
enum class RelocationType : std::uint8_t {
    Absolute        = 0,
    High            = 1,
    Low             = 2,
    HighLow         = 3,
    HighAdj         = 4,
    MachineSpecific5 = 5,
    Reserved        = 6,
    MachineSpecific7 = 7,
    MachineSpecific8 = 8,
    MachineSpecific9 = 9,
    Dir64           = 10,
};

struct RelocationEntry {
    std::uint16_t value;

    [[nodiscard]] RelocationType type() const noexcept {
        return static_cast<RelocationType>(value >> 12);
    }

    [[nodiscard]] std::uint16_t offset() const noexcept {
        return value & 0x0FFF;
    }
};
static_assert(sizeof(RelocationEntry) == 2);

// Runtime Function (x64 exception handling)
struct RuntimeFunction {
    std::uint32_t BeginAddress;
    std::uint32_t EndAddress;
    std::uint32_t UnwindInfoAddress;
};
static_assert(sizeof(RuntimeFunction) == 12);

// Unwind Info (x64)
struct UnwindInfo {
    std::uint8_t VersionAndFlags;
    std::uint8_t SizeOfProlog;
    std::uint8_t CountOfUnwindCodes;
    std::uint8_t FrameRegisterAndOffset;
    // UnwindCode array follows

    [[nodiscard]] std::uint8_t version() const noexcept { return VersionAndFlags & 0x07; }
    [[nodiscard]] std::uint8_t flags() const noexcept { return VersionAndFlags >> 3; }
    [[nodiscard]] std::uint8_t frame_register() const noexcept { return FrameRegisterAndOffset & 0x0F; }
    [[nodiscard]] std::uint8_t frame_offset() const noexcept { return FrameRegisterAndOffset >> 4; }
};

// Unwind flags
enum class UnwindFlags : std::uint8_t {
    Ehandler  = 0x01,  // Has exception handler
    Uhandler  = 0x02,  // Has termination handler
    ChainInfo = 0x04,  // Chained unwind info
};

// TLS Directory (32-bit)
struct TlsDirectory32 {
    std::uint32_t StartAddressOfRawData;
    std::uint32_t EndAddressOfRawData;
    std::uint32_t AddressOfIndex;
    std::uint32_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};

// TLS Directory (64-bit)
struct TlsDirectory64 {
    std::uint64_t StartAddressOfRawData;
    std::uint64_t EndAddressOfRawData;
    std::uint64_t AddressOfIndex;
    std::uint64_t AddressOfCallBacks;
    std::uint32_t SizeOfZeroFill;
    std::uint32_t Characteristics;
};

} // namespace picanha::loader::pe
