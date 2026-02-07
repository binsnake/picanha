// Signature Matching Plugin
// Matches functions against known signatures (FLIRT-like)

#include <picanha/plugin/plugin.hpp>
#include <picanha/plugin/function_pass.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/cfg.hpp>
#include <picanha/analysis/basic_block.hpp>

#include <spdlog/spdlog.h>
#include <xxhash.h>

#include <format>
#include <vector>
#include <unordered_map>
#include <string>
#include <fstream>

namespace {

using namespace picanha;
using namespace picanha::plugin;

// Signature entry
struct Signature {
    std::uint64_t hash;          // Hash of normalized bytes
    std::string name;            // Function name
    std::string library;         // Library name
    std::size_t min_size;        // Minimum function size
    std::size_t max_size;        // Maximum function size
    std::vector<std::uint8_t> prefix;  // Fixed prefix bytes
};

// Signature database
class SignatureDatabase {
public:
    bool load(const std::string& path) {
        // In a real implementation, would load from file
        // For now, add some hardcoded signatures

        // Common CRT functions
        add_signature(0x1234567890ABCDEF, "memcpy", "msvcrt", 16, 256);
        add_signature(0xFEDCBA0987654321, "memset", "msvcrt", 16, 128);
        add_signature(0xABCDEF1234567890, "strlen", "msvcrt", 8, 64);
        add_signature(0x0987654321FEDCBA, "strcmp", "msvcrt", 16, 128);

        // Common Windows API wrappers
        add_signature(0x1111222233334444, "GetLastError_wrapper", "user", 4, 16);

        return true;
    }

    const Signature* find(std::uint64_t hash) const {
        auto it = signatures_.find(hash);
        if (it != signatures_.end()) {
            return &it->second;
        }
        return nullptr;
    }

    const Signature* find_by_prefix(const std::vector<std::uint8_t>& bytes) const {
        for (const auto& [hash, sig] : signatures_) {
            if (sig.prefix.empty()) continue;

            if (bytes.size() >= sig.prefix.size()) {
                bool match = true;
                for (std::size_t i = 0; i < sig.prefix.size(); ++i) {
                    if (sig.prefix[i] != bytes[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) return &sig;
            }
        }
        return nullptr;
    }

    std::size_t size() const { return signatures_.size(); }

private:
    void add_signature(std::uint64_t hash, const std::string& name,
                       const std::string& library, std::size_t min_size,
                       std::size_t max_size) {
        signatures_[hash] = Signature{
            .hash = hash,
            .name = name,
            .library = library,
            .min_size = min_size,
            .max_size = max_size,
            .prefix = {},
        };
    }

    std::unordered_map<std::uint64_t, Signature> signatures_;
};

// Signature matching pass
class SignatureMatchPass : public IFunctionPass {
public:
    explicit SignatureMatchPass(SignatureDatabase& db) : db_(db) {}

    std::string name() const override {
        return "Signature Matcher";
    }

    std::string description() const override {
        return "Matches functions against known signatures";
    }

    PassResult run_on_function(
        analysis::Function& func,
        const analysis::CFG& cfg,
        PluginContext& ctx
    ) override {
        PassResult result;

        // Get function bytes for hashing
        auto bytes = get_function_bytes(func, cfg, ctx);
        if (bytes.empty()) {
            return result;
        }

        // Normalize bytes (remove variable parts)
        auto normalized = normalize_bytes(bytes);

        // Compute hash
        std::uint64_t hash = XXH64(normalized.data(), normalized.size(), 0);

        // Look up in database
        if (auto sig = db_.find(hash)) {
            result.suggested_name = sig->name;
            result.annotations.push_back(std::format("lib:{}", sig->library));
            result.modified = true;

            ctx.log(std::format("Matched signature: {} ({}) at 0x{:X}",
                sig->name, sig->library, func.entry_point()));
            return result;
        }

        // Try prefix matching
        if (auto sig = db_.find_by_prefix(bytes)) {
            result.suggested_name = sig->name + "_variant";
            result.annotations.push_back(std::format("lib:{}", sig->library));
            result.annotations.push_back("prefix_match");
            result.modified = true;

            ctx.log(std::format("Prefix matched: {} at 0x{:X}",
                sig->name, func.entry_point()));
        }

        return result;
    }

private:
    std::vector<std::uint8_t> get_function_bytes(
        const analysis::Function& func,
        const analysis::CFG& cfg,
        PluginContext& ctx
    ) const {
        std::vector<std::uint8_t> result;

        // Collect bytes from all blocks
        // In a real implementation, would read from binary
        // For now, just return placeholder

        return result;
    }

    std::vector<std::uint8_t> normalize_bytes(const std::vector<std::uint8_t>& bytes) const {
        std::vector<std::uint8_t> result = bytes;

        // Normalization rules:
        // 1. Zero out displacement/offset bytes in instructions
        // 2. Replace register operands with wildcards (if possible)
        // 3. Handle relocations

        // Simple implementation: just use the bytes as-is for now
        // A real implementation would use the disassembler to identify
        // variable parts of instructions

        return result;
    }

    SignatureDatabase& db_;
};

// Plugin implementation
class SignatureMatchPlugin : public IPlugin {
public:
    PluginInfo info() const override {
        return PluginInfo{
            .name = "Signature Matcher",
            .version = "1.0.0",
            .author = "Picanha Team",
            .description = "Matches functions against known signatures (FLIRT-like)",
            .type = PluginType::Analysis,
        };
    }

    bool initialize(PluginContext& ctx) override {
        // Load signature database
        if (!db_.load("signatures.db")) {
            // Not an error - we have built-in signatures
            ctx.log("Using built-in signatures");
        } else {
            ctx.log(std::format("Loaded {} signatures", db_.size()));
        }

        pass_ = std::make_unique<SignatureMatchPass>(db_);
        return true;
    }

    void shutdown() override {
        pass_.reset();
    }

    std::vector<IFunctionPass*> get_passes() override {
        if (pass_) {
            return {pass_.get()};
        }
        return {};
    }

private:
    SignatureDatabase db_;
    std::unique_ptr<SignatureMatchPass> pass_;
};

} // anonymous namespace

// Plugin entry point
PICANHA_PLUGIN_ENTRY(SignatureMatchPlugin)
