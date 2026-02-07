#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <picanha/core/span.hpp>
#include <picanha/core/result.hpp>
#include <iced_x86/iced_x86.hpp>
#include <optional>
#include <vector>

namespace picanha::disasm {

// Decoder configuration
struct DecoderConfig {
    Bitness bitness{Bitness::Bits64};
    bool amd_branches{false};       // AMD branch instructions
    bool force_reserved_nop{false}; // Force reserved NOP
    bool umov{false};               // UMOV instructions
    bool xbts{false};               // XBTS/IBTS instructions
    bool cmpxchg486a{false};        // CMPXCHG486A
    bool old_fpu{false};            // Old FPU instructions
    bool pcommit{false};            // PCOMMIT
    bool loadall286{false};         // LOADALL (286)
    bool loadall386{false};         // LOADALL (386)
    bool cl1invmb{false};           // CL1INVMB
    bool mov_tr{false};             // MOV to/from TR
    bool jmpe{false};               // JMPE
    bool cyrix{false};              // Cyrix instructions
    bool cyrix_smint{false};        // Cyrix SMINT 0F7E
    bool cyrix_dmi{false};          // Cyrix DMI

    [[nodiscard]] iced_x86::DecoderOptions::Value to_iced_options() const noexcept;
};

// Single instruction decoder
class Decoder {
public:
    explicit Decoder(Bitness bitness = Bitness::Bits64);
    Decoder(const DecoderConfig& config);

    // Decode at a specific address
    [[nodiscard]] Instruction decode(ByteSpan code, Address ip);

    // Decode multiple instructions
    [[nodiscard]] std::vector<Instruction> decode_all(ByteSpan code, Address ip);

    // Decode up to N instructions
    [[nodiscard]] std::vector<Instruction> decode_n(ByteSpan code, Address ip, std::size_t max_count);

    // Decode until a terminator (ret, jmp, etc.)
    [[nodiscard]] std::vector<Instruction> decode_until_terminator(ByteSpan code, Address ip);

    // Check if can decode more
    [[nodiscard]] bool can_decode() const noexcept;

    // Get current position
    [[nodiscard]] std::size_t position() const noexcept;

    // Get current IP
    [[nodiscard]] Address ip() const noexcept;

    // Reconfigure for new code segment
    void reconfigure(ByteSpan code, Address ip);

    // Get bitness
    [[nodiscard]] Bitness bitness() const noexcept { return config_.bitness; }

private:
    DecoderConfig config_;
    std::unique_ptr<iced_x86::Decoder> iced_decoder_;
    ByteSpan current_code_;
    Address current_ip_{0};
};

// Convenience function for single instruction decode
[[nodiscard]] inline Instruction decode_one(ByteSpan code, Address ip, Bitness bitness = Bitness::Bits64) {
    Decoder decoder(bitness);
    return decoder.decode(code, ip);
}

} // namespace picanha::disasm
