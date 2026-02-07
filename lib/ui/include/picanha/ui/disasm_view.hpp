#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/span.hpp>
#include <picanha/core/instruction.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/loader/pe/pe_sections.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/disasm/decoder.hpp>
#include <iced_x86/iced_x86.hpp>
#include <imgui.h>
#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <unordered_set>
#include <unordered_map>

namespace picanha::ui {

class Application;
class DisasmView;

// Symbol resolver that queries the application's symbol table
class AppSymbolResolver : public iced_x86::SymbolResolver {
public:
    explicit AppSymbolResolver(Application* app) : app_(app) {}

    [[nodiscard]] std::optional<iced_x86::SymbolResult> try_get_symbol(
        const iced_x86::Instruction& instruction,
        int operand,
        int instruction_operand,
        uint64_t address,
        int address_size) override;

private:
    Application* app_;
};

// Line types in the disassembly view
enum class DisasmLineType {
    Instruction,
    Label,
    FunctionHeader,
    FunctionEnd,
    SectionHeader,
    Comment,
    Data,
    Alignment,  // For "align X" directives (merged int3 padding)
    Separator,
    Empty,
};

// A single line in the disassembly listing
struct DisasmLine {
    DisasmLineType type{DisasmLineType::Empty};
    Address address{INVALID_ADDRESS};

    // For instructions
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands;
    std::string comment;

    // For labels/functions
    std::string label;

    // Target address for calls/jumps (for navigation)
    Address target_address{INVALID_ADDRESS};
    bool is_call{false};
    bool is_jump{false};
    bool is_data_ref{false};  // References data section

    // Cross-references
    std::size_t xref_count{0};

    // Flags
    bool is_call_target{false};
    bool is_jump_target{false};
    bool is_selected{false};
    bool is_current_ip{false};
    bool has_breakpoint{false};
};

// Control flow arrow (for intra-function jumps)
struct FlowArrow {
    std::size_t from_line;    // Line index of jump instruction
    std::size_t to_line;      // Line index of target
    int depth;                // Nesting depth (0 = leftmost)
    bool is_forward;          // True if jumping forward (down)
    bool is_conditional;      // Conditional vs unconditional
};

// Disassembly view configuration
struct DisasmViewConfig {
    bool show_addresses{true};
    bool show_bytes{true};
    bool show_xrefs{true};
    bool show_comments{true};
    bool show_flow_arrows{true};  // Control-flow arrows
    bool syntax_highlight{true};
    int bytes_per_line{8};
    int address_width{16};  // Hex digits
    float flow_arrow_margin{60.0f};  // Width of arrow margin
    ImU32 color_address{0xFF808080};
    ImU32 color_bytes{0xFF606060};
    ImU32 color_mnemonic{0xFF4090FF};
    ImU32 color_register{0xFFFF9040};
    ImU32 color_immediate{0xFF40FF40};
    ImU32 color_memory{0xFFFFFF40};
    ImU32 color_comment{0xFF808080};
    ImU32 color_label{0xFFFF4040};
    ImU32 color_string{0xFF40FFFF};
    ImU32 color_selection{0x40FFFFFF};
    ImU32 color_current{0x400000FF};
    ImU32 color_code_xref{0xFF40FF90};   // Green-ish for call/jmp targets
    ImU32 color_data_xref{0xFFFFB040};   // Orange for data references
    ImU32 color_flow_arrow{0xFF60A0FF};  // Blue for flow arrows
    ImU32 color_flow_arrow_back{0xFFFF8060};  // Orange for backward jumps
};

// Disassembly view
class DisasmView {
public:
    explicit DisasmView(Application* app);
    ~DisasmView();

    // Rendering
    void render();

    // Navigation
    void goto_address(Address address);
    void scroll_to_address(Address address);
    void center_on_address(Address address);

    // Selection
    void select_line(std::size_t line_index);
    void select_address(Address address);
    [[nodiscard]] Address selected_address() const;

    // Refresh/regenerate the view
    void refresh();

    // Configuration
    [[nodiscard]] DisasmViewConfig& config() { return config_; }
    [[nodiscard]] const DisasmViewConfig& config() const { return config_; }

    // View state
    [[nodiscard]] Address view_start() const { return view_start_; }
    [[nodiscard]] Address view_end() const { return view_end_; }
    [[nodiscard]] bool is_in_view(Address address) const;

private:
    // Line generation
    void generate_all_lines();
    void generate_lines(Address start, std::size_t count);
    void generate_function_lines(const analysis::Function& func);
    void collect_branch_targets(Address start, std::size_t count);
    DisasmLine make_instruction_line(const Instruction& instr, ByteSpan bytes);
    DisasmLine make_label_line(Address address, const std::string& name);
    DisasmLine make_function_header(const analysis::Function& func);
    DisasmLine make_section_header(const loader::pe::Section& section);
    DisasmLine make_data_line(Address address, std::uint8_t byte);
    DisasmLine make_loc_label(Address address);
    DisasmLine make_alignment_line(Address address, Size alignment_size);
    std::string format_xref_comment(Address address) const;

    // Helper to count consecutive int3 bytes for alignment detection
    Size count_int3_bytes(Address start, Size max_count) const;

    // Rendering helpers
    void render_line(const DisasmLine& line, std::size_t line_index, float margin_width = 0.0f);
    void render_address(Address address);
    void render_bytes(const std::vector<std::uint8_t>& bytes);
    void render_mnemonic(const std::string& mnemonic, bool is_call, bool is_jump);
    void render_operands(const DisasmLine& line);
    void render_comment(const std::string& comment);
    void render_xrefs(Address address);

    // Navigation
    void navigate_to_target(const DisasmLine& line);

    // Context menu
    void render_context_menu();

    // Keyboard handling
    void handle_keyboard();

    // Scrolling
    void ensure_visible(Address address);
    void update_scroll();

    // Formatting
    std::string format_address(Address address) const;
    std::string format_operand(const Instruction& instr, int operand_index) const;

    Application* app_;
    DisasmViewConfig config_;
    disasm::Decoder decoder_;
    AppSymbolResolver symbol_resolver_;
    iced_x86::IntelFormatter formatter_;

    // Lines
    std::vector<DisasmLine> lines_;
    Address view_start_{INVALID_ADDRESS};
    Address view_end_{INVALID_ADDRESS};

    // Selection
    std::size_t selected_line_{0};
    Address selected_address_{INVALID_ADDRESS};
    std::optional<Address> goto_address_;

    // Scroll state
    float scroll_y_{0.0f};
    bool scroll_to_selection_{false};

    // Search
    std::string search_text_;
    bool search_open_{false};

    // Xref navigation
    Address xref_nav_address_{INVALID_ADDRESS};
    std::size_t xref_nav_index_{0};
    bool show_xref_popup_{false};
    std::vector<analysis::XRef> xref_popup_refs_;

    // Cached data
    std::unordered_set<Address> call_targets_;
    std::unordered_set<Address> jump_targets_;
    std::unordered_set<Address> function_ends_;  // Addresses where functions end (for align detection)

    // Control flow arrows
    std::vector<FlowArrow> flow_arrows_;
    std::unordered_map<Address, std::size_t> address_to_line_;  // Map address to line index

    // Flow arrow helpers
    void calculate_flow_arrows();
    void render_flow_arrows(std::size_t first_visible, std::size_t last_visible, float line_height);
    int calculate_arrow_depth(const FlowArrow& arrow, const std::vector<FlowArrow>& arrows);
};

} // namespace picanha::ui
