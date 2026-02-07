#include "picanha/disasm/decoder.hpp"

namespace picanha::disasm {

iced_x86::DecoderOptions::Value DecoderConfig::to_iced_options() const noexcept {
    using namespace iced_x86;
    DecoderOptions::Value opts = DecoderOptions::NONE;

    if (amd_branches)       opts |= DecoderOptions::AMD;
    if (force_reserved_nop) opts |= DecoderOptions::FORCE_RESERVED_NOP;
    if (umov)               opts |= DecoderOptions::UMOV;
    if (xbts)               opts |= DecoderOptions::XBTS;
    if (cmpxchg486a)        opts |= DecoderOptions::CMPXCHG486A;
    if (old_fpu)            opts |= DecoderOptions::OLD_FPU;
    if (pcommit)            opts |= DecoderOptions::PCOMMIT;
    if (loadall286)         opts |= DecoderOptions::LOADALL286;
    if (loadall386)         opts |= DecoderOptions::LOADALL386;
    if (cl1invmb)           opts |= DecoderOptions::CL1INVMB;
    if (mov_tr)             opts |= DecoderOptions::MOV_TR;
    if (jmpe)               opts |= DecoderOptions::JMPE;
    if (cyrix)              opts |= DecoderOptions::CYRIX;
    if (cyrix_smint)        opts |= DecoderOptions::CYRIX_SMINT_0F7E;
    if (cyrix_dmi)          opts |= DecoderOptions::CYRIX_DMI;

    return opts;
}

Decoder::Decoder(Bitness bitness) {
    config_.bitness = bitness;
}

Decoder::Decoder(const DecoderConfig& config)
    : config_(config)
{}

Instruction Decoder::decode(ByteSpan code, Address ip) {
    std::uint32_t bits = static_cast<std::uint32_t>(config_.bitness);
    iced_x86::Decoder decoder(bits, code, ip, config_.to_iced_options());

    auto result = decoder.decode();
    if (!result) {
        // Return invalid instruction
        return Instruction{};
    }

    return Instruction(*result);
}

std::vector<Instruction> Decoder::decode_all(ByteSpan code, Address ip) {
    std::vector<Instruction> instructions;
    instructions.reserve(code.size() / 4); // Rough estimate

    std::uint32_t bits = static_cast<std::uint32_t>(config_.bitness);
    iced_x86::Decoder decoder(bits, code, ip, config_.to_iced_options());

    while (decoder.can_decode()) {
        auto result = decoder.decode();
        if (!result) {
            break;
        }
        instructions.emplace_back(*result);
    }

    return instructions;
}

std::vector<Instruction> Decoder::decode_n(ByteSpan code, Address ip, std::size_t max_count) {
    std::vector<Instruction> instructions;
    instructions.reserve(max_count);

    std::uint32_t bits = static_cast<std::uint32_t>(config_.bitness);
    iced_x86::Decoder decoder(bits, code, ip, config_.to_iced_options());

    while (decoder.can_decode() && instructions.size() < max_count) {
        auto result = decoder.decode();
        if (!result) {
            break;
        }
        instructions.emplace_back(*result);
    }

    return instructions;
}

std::vector<Instruction> Decoder::decode_until_terminator(ByteSpan code, Address ip) {
    std::vector<Instruction> instructions;
    instructions.reserve(64);

    std::uint32_t bits = static_cast<std::uint32_t>(config_.bitness);
    iced_x86::Decoder decoder(bits, code, ip, config_.to_iced_options());

    while (decoder.can_decode()) {
        auto result = decoder.decode();
        if (!result) {
            break;
        }

        Instruction instr(*result);
        instructions.push_back(instr);

        // Check if terminator
        if (instr.is_terminator()) {
            break;
        }
    }

    return instructions;
}

bool Decoder::can_decode() const noexcept {
    return iced_decoder_ && iced_decoder_->can_decode();
}

std::size_t Decoder::position() const noexcept {
    return iced_decoder_ ? iced_decoder_->position() : 0;
}

Address Decoder::ip() const noexcept {
    return iced_decoder_ ? iced_decoder_->ip() : current_ip_;
}

void Decoder::reconfigure(ByteSpan code, Address ip) {
    current_code_ = code;
    current_ip_ = ip;

    std::uint32_t bits = static_cast<std::uint32_t>(config_.bitness);
    iced_decoder_ = std::make_unique<iced_x86::Decoder>(bits, code, ip, config_.to_iced_options());
}

} // namespace picanha::disasm
