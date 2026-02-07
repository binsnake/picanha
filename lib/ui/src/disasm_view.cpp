#include <picanha/ui/disasm_view.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>
#include <cctype>

namespace picanha::ui {

// AppSymbolResolver implementation
std::optional<iced_x86::SymbolResult> AppSymbolResolver::try_get_symbol(
    const iced_x86::Instruction& /*instruction*/,
    int /*operand*/,
    int /*instruction_operand*/,
    uint64_t address,
    int address_size)
{
    Address addr = static_cast<Address>(address);

    // Check symbol table first (imports, exports)
    if (auto* sym = app_->symbols().find_at(addr)) {
        if (!sym->name.empty()) {
            return iced_x86::SymbolResult(address, sym->name);
        }
    }

    // Check functions from exception directory (like CLI does)
    if (auto binary = app_->binary()) {
        if (auto* func = binary->find_function(addr)) {
            if (func->begin_address == addr) {
                // Check if there's a name from exports
                if (auto name = binary->get_symbol_name(addr)) {
                    return iced_x86::SymbolResult(address, *name);
                }
                return iced_x86::SymbolResult(address, std::format("sub_{:X}", addr));
            }
        }

        // Check if address is in a data section (.data, .rdata, etc.)
        if (auto* section = binary->find_section(addr)) {
            if (!section->is_executable()) {
                // Use size-based prefix
                std::string_view prefix;
                switch (address_size) {
                    case 1:  prefix = "byte"; break;
                    case 2:  prefix = "word"; break;
                    case 4:  prefix = "dword"; break;
                    case 8:  prefix = "qword"; break;
                    case 16: prefix = "oword"; break;
                    default: prefix = "unk"; break;
                }
                return iced_x86::SymbolResult(address, std::format("{}_{:X}", prefix, addr));
            }
        }
    }

    return std::nullopt;
}

DisasmView::DisasmView(Application* app)
    : app_(app)
    , symbol_resolver_(app)
    , formatter_()
{
    // Explicitly set symbol resolver after construction to ensure proper initialization
    formatter_.set_symbol_resolver(&symbol_resolver_);
}

DisasmView::~DisasmView() = default;

void DisasmView::render() {
    handle_keyboard();

    // Toolbar
    if (ImGui::Button("Go to...")) {
        // TODO: Open goto dialog
    }
    ImGui::SameLine();
    ImGui::Checkbox("Bytes", &config_.show_bytes);
    ImGui::SameLine();
    ImGui::Checkbox("XRefs", &config_.show_xrefs);
    ImGui::SameLine();
    ImGui::Checkbox("Flow", &config_.show_flow_arrows);

    ImGui::Separator();

    // Calculate margin width for flow arrows
    float margin_width = config_.show_flow_arrows ? config_.flow_arrow_margin : 0.0f;

    // Main content
    ImGuiWindowFlags flags = ImGuiWindowFlags_HorizontalScrollbar;
    if (ImGui::BeginChild("DisasmContent", ImVec2(0, 0), ImGuiChildFlags_None, flags)) {
        // Calculate visible area
        float line_height = ImGui::GetTextLineHeightWithSpacing();
        float scroll_y = ImGui::GetScrollY();
        float window_height = ImGui::GetWindowHeight();

        int first_visible = static_cast<int>(scroll_y / line_height);
        int visible_count = static_cast<int>(window_height / line_height) + 2;

        // Render visible lines
        if (!lines_.empty()) {
            first_visible = std::clamp(first_visible, 0, static_cast<int>(lines_.size()) - 1);
            int last_visible = std::min(first_visible + visible_count, static_cast<int>(lines_.size()));

            // Render flow arrows first (behind text)
            if (config_.show_flow_arrows && !flow_arrows_.empty()) {
                render_flow_arrows(static_cast<std::size_t>(first_visible),
                                   static_cast<std::size_t>(last_visible), line_height);
            }

            // Set cursor to first visible line with margin offset
            ImGui::SetCursorPosY(first_visible * line_height);

            for (int i = first_visible; i < last_visible; ++i) {
                render_line(lines_[i], static_cast<std::size_t>(i), margin_width);
            }

            // Add dummy space for scrolling
            float total_height = lines_.size() * line_height;
            ImGui::SetCursorPosY(total_height);
        } else {
            ImGui::TextDisabled("No disassembly available");
            ImGui::TextDisabled("Load a binary and run analysis to see disassembly");
        }

        // Handle scrolling to selection
        if (scroll_to_selection_ && selected_line_ < lines_.size()) {
            float target_y = selected_line_ * line_height;
            ImGui::SetScrollY(target_y - window_height / 2);
            scroll_to_selection_ = false;
        }
    }
    ImGui::EndChild();

    // Context menu
    render_context_menu();

    // XRef popup (triggered by X key)
    if (ImGui::BeginPopup("XRefs")) {
        ImGui::Text("Cross-references to 0x%llX:", static_cast<unsigned long long>(xref_nav_address_));
        ImGui::Separator();

        if (xref_popup_refs_.empty()) {
            ImGui::TextDisabled("No cross-references found");
        } else {
            for (std::size_t i = 0; i < xref_popup_refs_.size(); ++i) {
                const auto& ref = xref_popup_refs_[i];

                // Determine if we're showing refs TO or FROM the selected address
                bool is_ref_to = (ref.to == xref_nav_address_);
                Address nav_addr = is_ref_to ? ref.from : ref.to;

                // Format type
                const char* type_str = "?";
                switch (ref.type) {
                    case analysis::XRefType::Call: type_str = "call"; break;
                    case analysis::XRefType::IndirectCall: type_str = "icall"; break;
                    case analysis::XRefType::Jump: type_str = "jmp"; break;
                    case analysis::XRefType::IndirectJump: type_str = "ijmp"; break;
                    case analysis::XRefType::ConditionalJump: type_str = "cjmp"; break;
                    case analysis::XRefType::Read: type_str = "read"; break;
                    case analysis::XRefType::Write: type_str = "write"; break;
                    case analysis::XRefType::Offset: type_str = "lea"; break;
                    default: break;
                }

                // Find function name for the address
                std::string func_name;
                for (const auto& func : app_->functions()) {
                    if (nav_addr >= func.start_address() && nav_addr < func.end_address()) {
                        func_name = func.name().empty()
                            ? std::format("sub_{:X}", func.start_address())
                            : func.name();
                        Address offset = nav_addr - func.start_address();
                        if (offset > 0) {
                            func_name += std::format("+0x{:X}", offset);
                        }
                        break;
                    }
                }

                if (func_name.empty()) {
                    func_name = std::format("{:016X}", nav_addr);
                }

                // Display entry
                char label[256];
                snprintf(label, sizeof(label), "%s  %s  %s",
                    is_ref_to ? "from:" : "to:  ",
                    type_str,
                    func_name.c_str());

                if (ImGui::Selectable(label)) {
                    goto_address(nav_addr);
                    ImGui::CloseCurrentPopup();
                }
            }
        }

        ImGui::EndPopup();
    }
}

void DisasmView::goto_address(Address address) {
    if (address == INVALID_ADDRESS) return;

    goto_address_ = address;

    // Generate all lines if view is empty
    if (lines_.empty()) {
        generate_all_lines();
    }

    // Find line containing this address
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].address == address) {
            selected_line_ = i;
            selected_address_ = address;
            scroll_to_selection_ = true;
            return;
        }
    }

    // Address not found - find closest line
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].address != INVALID_ADDRESS && lines_[i].address >= address) {
            selected_line_ = i > 0 ? i - 1 : 0;
            selected_address_ = lines_[selected_line_].address;
            scroll_to_selection_ = true;
            return;
        }
    }
}

void DisasmView::scroll_to_address(Address address) {
    goto_address(address);
}

void DisasmView::center_on_address(Address address) {
    goto_address(address);
}

void DisasmView::select_line(std::size_t line_index) {
    if (line_index < lines_.size()) {
        selected_line_ = line_index;
        selected_address_ = lines_[line_index].address;
    }
}

void DisasmView::select_address(Address address) {
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].address == address) {
            select_line(i);
            break;
        }
    }
}

Address DisasmView::selected_address() const {
    return selected_address_;
}

bool DisasmView::is_in_view(Address address) const {
    return address >= view_start_ && address < view_end_;
}

void DisasmView::refresh() {
    // Regenerate all lines for the entire binary
    generate_all_lines();
}

void DisasmView::generate_all_lines() {
    auto binary = app_->binary();
    if (!binary) return;

    const auto& sections = binary->sections();
    if (sections.empty()) return;

    // Find the first section by address
    Address first_addr = sections[0].virtual_address;
    for (const auto& sec : sections) {
        if (sec.virtual_address < first_addr) {
            first_addr = sec.virtual_address;
        }
    }

    // Generate a reasonable number of lines (50k max to avoid freezing)
    // TODO: Implement virtual scrolling for large binaries
    generate_lines(first_addr, 50000);
}

void DisasmView::collect_branch_targets(Address start, std::size_t count) {
    auto binary = app_->binary();
    if (!binary) return;

    Address current = start;
    std::size_t scanned = 0;

    while (scanned < count) {
        auto* section = binary->find_section(current);
        if (!section) break;

        // Only scan code sections
        if (!section->is_executable() && !section->contains_code()) {
            current = section->virtual_address + section->virtual_size;
            continue;
        }

        // Check bounds
        Address section_end = section->virtual_address + section->virtual_size;
        if (current >= section_end) {
            // Find next section
            bool found = false;
            for (const auto& sec : binary->sections()) {
                if (sec.virtual_address > current) {
                    current = sec.virtual_address;
                    found = true;
                    break;
                }
            }
            if (!found) break;
            continue;
        }

        // Decode instruction
        auto bytes = binary->read(current, 15);
        if (!bytes || bytes->empty()) {
            current++;
            scanned++;
            continue;
        }

        auto instr = decoder_.decode(*bytes, current);
        if (instr.length() == 0) {
            current++;
            scanned++;
            continue;
        }

        // Check for branch/call targets
        const auto& raw = instr.raw();
        auto op0_kind = raw.op_kind(0);

        if (op0_kind == iced_x86::OpKind::NEAR_BRANCH64 ||
            op0_kind == iced_x86::OpKind::NEAR_BRANCH32 ||
            op0_kind == iced_x86::OpKind::NEAR_BRANCH16) {
            Address target = raw.near_branch_target();
            if (instr.is_call()) {
                call_targets_.insert(target);
            } else if (instr.is_branch()) {
                jump_targets_.insert(target);
            }
        }

        current += instr.length();
        scanned++;
    }
}

void DisasmView::generate_lines(Address start, std::size_t count) {
    lines_.clear();
    jump_targets_.clear();
    call_targets_.clear();
    function_ends_.clear();
    view_start_ = start;

    auto binary = app_->binary();
    if (!binary) return;

    // Pre-scan to collect jump/call targets for loc_ labels
    collect_branch_targets(start, count);

    // Collect function end addresses for alignment detection
    for (const auto& func : app_->functions()) {
        if (func.end_address() > func.start_address()) {
            function_ends_.insert(func.end_address());
        }
    }

    // Find the section containing the start address
    const loader::pe::Section* current_section = binary->find_section(start);

    // If start address not in any section, find the first section at or after start
    if (!current_section) {
        for (const auto& sec : binary->sections()) {
            if (sec.virtual_address >= start) {
                current_section = &sec;
                start = sec.virtual_address;
                break;
            }
        }
    }

    if (!current_section) return;

    Address current = start;
    std::size_t generated = 0;
    const loader::pe::Section* last_section = nullptr;

    while (generated < count) {
        // Check if we're still in a valid section
        current_section = binary->find_section(current);
        if (!current_section) {
            // Find next section
            const loader::pe::Section* next_section = nullptr;
            for (const auto& sec : binary->sections()) {
                if (sec.virtual_address > current) {
                    if (!next_section || sec.virtual_address < next_section->virtual_address) {
                        next_section = &sec;
                    }
                }
            }
            if (next_section) {
                current_section = next_section;
                current = next_section->virtual_address;
            } else {
                break; // No more sections
            }
        }

        // Check if current address is past the end of the image
        if (current >= binary->image_base() + binary->address_range().end - binary->address_range().start) {
            break;
        }

        // Add section header when entering a new section
        if (current_section != last_section) {
            lines_.push_back(make_section_header(*current_section));
            generated++;
            last_section = current_section;
        }

        // Handle differently based on section type
        bool is_code_section = current_section->is_executable() || current_section->contains_code();

        if (is_code_section) {
            // Check if we're at a function end and there are int3 bytes (alignment padding)
            if (function_ends_.contains(current)) {
                Size int3_count = count_int3_bytes(current, 64);  // Check up to 64 bytes
                if (int3_count > 0) {
                    // Calculate alignment - find next power of 2 boundary
                    Address next_aligned = current + int3_count;
                    Size alignment = 0;
                    // Common alignments: 16, 32, 64 bytes
                    for (Size align : {64ULL, 32ULL, 16ULL, 8ULL, 4ULL}) {
                        if ((next_aligned & (align - 1)) == 0) {
                            alignment = align;
                            break;
                        }
                    }
                    if (alignment == 0) alignment = int3_count;

                    lines_.push_back(make_alignment_line(current, alignment));
                    current += int3_count;
                    generated++;
                    continue;
                }
            }

            // Check for function header
            bool is_func_start = false;
            for (const auto& func : app_->functions()) {
                if (func.start_address() == current) {
                    lines_.push_back(make_function_header(func));
                    generated++;
                    is_func_start = true;
                    break;
                }
            }

            // Check for symbol/label
            auto sym = app_->symbols().find_at(current);
            bool has_symbol = sym && !sym->name.empty() && sym->type != analysis::SymbolType::Function;
            if (has_symbol) {
                lines_.push_back(make_label_line(current, sym->name));
                generated++;
            }

            // Check for jump target (add loc_ label if not already labeled)
            if (!is_func_start && !has_symbol && jump_targets_.contains(current)) {
                lines_.push_back(make_loc_label(current));
                generated++;
            }

            // Decode instruction
            auto bytes = binary->read(current, 15);
            if (bytes && !bytes->empty()) {
                auto instr = decoder_.decode(*bytes, current);
                if (instr.length() > 0) {
                    lines_.push_back(make_instruction_line(instr, *bytes));
                    current += instr.length();
                    generated++;
                    continue;
                }
            }
            // Invalid instruction, output as data byte
            {
                auto byte_data = binary->read(current, 1);
                std::uint8_t byte_val = (byte_data && !byte_data->empty()) ? (*byte_data)[0] : 0;
                lines_.push_back(make_data_line(current, byte_val));
                current++;
                generated++;
            }
        } else {
            // Data section - skip to next section (view data in hex view instead)
            // Just add a note about the section size
            DisasmLine note;
            note.type = DisasmLineType::Comment;
            note.address = current_section->virtual_address;
            note.comment = std::format("Data section: {} bytes (use Hex View)", current_section->virtual_size);
            lines_.push_back(note);
            generated++;

            // Skip to end of this section
            current = current_section->virtual_address + current_section->virtual_size;
        }
    }

    view_end_ = current;

    // Build address-to-line index for flow arrows
    address_to_line_.clear();
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].address != INVALID_ADDRESS) {
            address_to_line_[lines_[i].address] = i;
        }
    }

    // Calculate flow arrows for intra-function jumps
    calculate_flow_arrows();
}

void DisasmView::generate_function_lines(const analysis::Function& func) {
    lines_.clear();
    view_start_ = func.start_address();

    // Add function header
    lines_.push_back(make_function_header(func));

    // TODO: Iterate through blocks in order and generate lines
    // For now, just generate from entry point
    generate_lines(func.start_address(), 500);
}

DisasmLine DisasmView::make_instruction_line(const Instruction& instr, ByteSpan bytes) {
    DisasmLine line;
    line.type = DisasmLineType::Instruction;
    line.address = instr.ip();
    line.bytes.assign(bytes.begin(), bytes.begin() + instr.length());

    // Format the instruction
    auto formatted = formatter_.format_to_string(instr.raw());
    // Split into mnemonic and operands at first space
    auto space_pos = formatted.find(' ');
    if (space_pos != std::string::npos) {
        line.mnemonic = formatted.substr(0, space_pos);
        line.operands = formatted.substr(space_pos + 1);
    } else {
        line.mnemonic = formatted;
        line.operands.clear();
    }

    // Check xrefs
    line.xref_count = app_->xrefs().get_refs_to(instr.ip()).size();

    // Check if call/jump target
    line.is_call_target = call_targets_.contains(instr.ip());
    line.is_jump_target = jump_targets_.contains(instr.ip());

    // Extract target address for calls/jumps
    const auto& raw = instr.raw();
    auto op0_kind = raw.op_kind(0);

    // Check for direct call/jump (near branch)
    if (op0_kind == iced_x86::OpKind::NEAR_BRANCH64 ||
        op0_kind == iced_x86::OpKind::NEAR_BRANCH32 ||
        op0_kind == iced_x86::OpKind::NEAR_BRANCH16) {
        line.target_address = raw.near_branch_target();
        line.is_call = instr.is_call();
        line.is_jump = instr.is_branch();
    }
    // Check for indirect call/jump through memory (RIP-relative)
    else if (raw.memory_base() == iced_x86::Register::RIP) {
        line.target_address = raw.memory_displacement64();
        line.is_call = instr.is_call();
        line.is_jump = instr.is_branch() && !instr.is_call();
        // For indirect calls, it's still a data ref (reads from IAT)
        line.is_data_ref = !instr.is_call() && !instr.is_branch();
    }
    // Check for memory operand referencing data (not a call/jump)
    else if (!instr.is_call() && !instr.is_branch()) {
        if (raw.memory_base() == iced_x86::Register::RIP) {
            line.target_address = raw.memory_displacement64();
            line.is_data_ref = true;
        }
    }

    return line;
}

DisasmLine DisasmView::make_label_line(Address address, const std::string& name) {
    DisasmLine line;
    line.type = DisasmLineType::Label;
    line.address = address;
    line.label = name;
    line.xref_count = app_->xrefs().get_refs_to(address).size();
    return line;
}

DisasmLine DisasmView::make_function_header(const analysis::Function& func) {
    DisasmLine line;
    line.type = DisasmLineType::FunctionHeader;
    line.address = func.start_address();
    line.label = func.name().empty() ? std::format("sub_{:X}", func.start_address()) : func.name();
    line.xref_count = app_->xrefs().get_refs_to(func.start_address()).size();
    return line;
}

DisasmLine DisasmView::make_section_header(const loader::pe::Section& section) {
    DisasmLine line;
    line.type = DisasmLineType::SectionHeader;
    line.address = section.virtual_address;
    line.label = section.name;

    // Add section info to comment (RWX order like Unix)
    std::string perms;
    if (has_permission(section.permissions, MemoryPermissions::Read)) perms += "R";
    if (section.is_writable()) perms += "W";
    if (section.is_executable()) perms += "X";

    line.comment = std::format("Size: 0x{:X}  Perms: {}", section.virtual_size, perms);
    return line;
}

DisasmLine DisasmView::make_data_line(Address address, std::uint8_t byte) {
    DisasmLine line;
    line.type = DisasmLineType::Data;
    line.address = address;
    line.bytes = {byte};
    line.mnemonic = "db";
    line.operands = std::format("0x{:02X}", byte);

    // Check for xrefs to this address
    line.xref_count = app_->xrefs().get_refs_to(address).size();

    // Add ASCII representation if printable
    if (byte >= 0x20 && byte < 0x7F) {
        line.comment = std::format("'{}'", static_cast<char>(byte));
    }

    return line;
}

DisasmLine DisasmView::make_loc_label(Address address) {
    DisasmLine line;
    line.type = DisasmLineType::Label;
    line.address = address;
    line.label = std::format("loc_{:X}", address);
    line.xref_count = app_->xrefs().get_refs_to(address).size();
    line.is_jump_target = true;
    return line;
}

DisasmLine DisasmView::make_alignment_line(Address address, Size alignment_size) {
    DisasmLine line;
    line.type = DisasmLineType::Alignment;
    line.address = address;
    line.mnemonic = "align";
    line.operands = std::format("{:X}h", alignment_size);
    return line;
}

Size DisasmView::count_int3_bytes(Address start, Size max_count) const {
    auto binary = app_->binary();
    if (!binary) return 0;

    auto bytes = binary->read(start, max_count);
    if (!bytes || bytes->empty()) return 0;

    Size count = 0;
    for (auto byte : *bytes) {
        if (byte == 0xCC) {  // int3 opcode
            count++;
        } else {
            break;
        }
    }
    return count;
}

std::string DisasmView::format_xref_comment(Address address) const {
    auto refs = app_->xrefs().get_refs_to(address);
    if (refs.empty()) return "";

    std::string result;
    std::size_t shown = 0;
    const std::size_t max_refs = 3;  // Show at most 3 refs inline

    for (const auto& ref : refs) {
        if (shown >= max_refs) {
            result += std::format(" (+{} more)", refs.size() - shown);
            break;
        }

        if (!result.empty()) result += ", ";

        // Determine ref type symbol
        char type_char = '?';
        bool is_up = ref.from > address;  // Arrow direction
        switch (ref.type) {
            case analysis::XRefType::Call:
            case analysis::XRefType::IndirectCall:
                type_char = 'p';  // procedure call
                break;
            case analysis::XRefType::Jump:
            case analysis::XRefType::IndirectJump:
                type_char = 'j';  // jump
                break;
            case analysis::XRefType::ConditionalJump:
                type_char = 'j';  // conditional jump
                break;
            case analysis::XRefType::Read:
                type_char = 'r';  // read
                break;
            case analysis::XRefType::Write:
                type_char = 'w';  // write
                break;
            case analysis::XRefType::Offset:
                type_char = 'o';  // offset/lea
                break;
            default:
                type_char = 'x';
                break;
        }

        // Format like IDA: sub_XXX+0x10↑j
        // Find containing function for the source
        std::string source_name;
        for (const auto& func : app_->functions()) {
            if (ref.from >= func.start_address() && ref.from < func.end_address()) {
                std::string func_name = func.name().empty()
                    ? std::format("sub_{:X}", func.start_address())
                    : func.name();
                Address offset = ref.from - func.start_address();
                if (offset > 0) {
                    source_name = std::format("{}+0x{:X}", func_name, offset);
                } else {
                    source_name = func_name;
                }
                break;
            }
        }

        if (source_name.empty()) {
            source_name = std::format("{:X}", ref.from);
        }

        // Use Unicode arrows and separate type char with space
        const char* arrow = is_up ? "\xe2\x86\x91" : "\xe2\x86\x93";  // ↑ or ↓
        result += std::format("{}{}:{}", source_name, arrow, type_char);
        shown++;
    }

    return result;
}

void DisasmView::render_line(const DisasmLine& line, std::size_t line_index, float margin_width) {
    bool is_selected = (line_index == selected_line_);

    // Selection highlight (includes margin area)
    if (is_selected) {
        ImVec2 pos = ImGui::GetCursorScreenPos();
        ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetTextLineHeightWithSpacing());
        ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y),
            config_.color_selection);
    }

    // Handle click
    ImVec2 cursor_pos = ImGui::GetCursorPos();
    ImGui::PushID(static_cast<int>(line_index));

    if (ImGui::InvisibleButton("##line", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetTextLineHeightWithSpacing()))) {
        select_line(line_index);
        if (line.address != INVALID_ADDRESS) {
            app_->select_address(line.address);
        }
    }

    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
        // Navigate to target on double-click (for jumps/calls/data refs)
        navigate_to_target(line);
    }

    ImGui::PopID();

    // Reset cursor and render content, offset by margin
    cursor_pos.x += margin_width;
    ImGui::SetCursorPos(cursor_pos);

    switch (line.type) {
        case DisasmLineType::SectionHeader:
            ImGui::TextColored(ImColor(0xFFFFFF00).Value, "; ============= SECTION: %s =============", line.label.c_str());
            if (!line.comment.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImColor(config_.color_comment).Value, " ; %s", line.comment.c_str());
            }
            break;

        case DisasmLineType::FunctionHeader: {
            render_xrefs(line.address);
            ImGui::SameLine();
            ImGui::TextColored(ImColor(config_.color_label).Value, "; ============= FUNCTION: %s =============", line.label.c_str());
            // Show xref sources
            if (config_.show_xrefs && line.xref_count > 0) {
                auto xref_comment = format_xref_comment(line.address);
                if (!xref_comment.empty()) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImColor(config_.color_comment).Value, " ; XREF: %s", xref_comment.c_str());
                }
            }
            break;
        }

        case DisasmLineType::Label: {
            render_xrefs(line.address);
            ImGui::SameLine();
            ImGui::TextColored(ImColor(config_.color_label).Value, "%s:", line.label.c_str());
            // Show xref sources for jump targets
            if (config_.show_xrefs && line.xref_count > 0) {
                auto xref_comment = format_xref_comment(line.address);
                if (!xref_comment.empty()) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImColor(config_.color_comment).Value, " ; CODE XREF: %s", xref_comment.c_str());
                }
            }
            break;
        }

        case DisasmLineType::Instruction:
            if (config_.show_addresses) {
                render_address(line.address);
                ImGui::SameLine();
            }
            if (config_.show_bytes) {
                render_bytes(line.bytes);
                ImGui::SameLine();
            }
            render_mnemonic(line.mnemonic, line.is_call, line.is_jump);
            ImGui::SameLine();
            render_operands(line);
            if (config_.show_comments && !line.comment.empty()) {
                ImGui::SameLine();
                render_comment(line.comment);
            }
            break;

        case DisasmLineType::Data:
            if (config_.show_xrefs && line.xref_count > 0) {
                render_xrefs(line.address);
                ImGui::SameLine();
            }
            if (config_.show_addresses) {
                render_address(line.address);
                ImGui::SameLine();
            }
            if (config_.show_bytes) {
                render_bytes(line.bytes);
                ImGui::SameLine();
            }
            ImGui::TextColored(ImColor(config_.color_mnemonic).Value, "%-8s", line.mnemonic.c_str());
            ImGui::SameLine();
            ImGui::TextColored(ImColor(config_.color_immediate).Value, "%s", line.operands.c_str());
            if (!line.comment.empty()) {
                ImGui::SameLine();
                render_comment(line.comment);
            }
            break;

        case DisasmLineType::Comment:
            ImGui::TextColored(ImColor(config_.color_comment).Value, "; %s", line.comment.c_str());
            break;

        case DisasmLineType::Alignment:
            if (config_.show_addresses) {
                render_address(line.address);
                ImGui::SameLine();
            }
            // Show as directive like IDA: "align 10h"
            ImGui::TextColored(ImColor(config_.color_mnemonic).Value, "%-8s", line.mnemonic.c_str());
            ImGui::SameLine();
            ImGui::TextColored(ImColor(config_.color_immediate).Value, "%s", line.operands.c_str());
            break;

        case DisasmLineType::Separator:
            ImGui::Separator();
            break;

        case DisasmLineType::Empty:
        case DisasmLineType::FunctionEnd:
        default:
            ImGui::NewLine();
            break;
    }
}

void DisasmView::render_address(Address address) {
    ImGui::TextColored(ImColor(config_.color_address).Value, "%s", format_address(address).c_str());
}

void DisasmView::render_bytes(const std::vector<std::uint8_t>& bytes) {
    std::string hex;
    for (std::size_t i = 0; i < bytes.size() && i < static_cast<std::size_t>(config_.bytes_per_line); ++i) {
        hex += std::format("{:02X} ", bytes[i]);
    }
    // Pad to fixed width
    while (hex.length() < static_cast<std::size_t>(config_.bytes_per_line) * 3) {
        hex += "   ";
    }
    ImGui::TextColored(ImColor(config_.color_bytes).Value, "%s", hex.c_str());
}

void DisasmView::render_mnemonic(const std::string& mnemonic, bool is_call, bool is_jump) {
    ImU32 color = config_.color_mnemonic;
    if (is_call || is_jump) {
        color = config_.color_code_xref;  // Green-ish for calls/jumps
    }
    ImGui::TextColored(ImColor(color).Value, "%-8s", mnemonic.c_str());
}

void DisasmView::render_operands(const DisasmLine& line) {
    // Color operands based on whether they contain xrefs
    ImU32 color = config_.color_register;  // Default

    if (line.target_address != INVALID_ADDRESS) {
        if (line.is_data_ref) {
            color = config_.color_data_xref;  // Orange for data refs
        } else if (line.is_call || line.is_jump) {
            color = config_.color_code_xref;  // Green for code refs
        }
    }

    ImGui::TextColored(ImColor(color).Value, "%s", line.operands.c_str());
}

void DisasmView::navigate_to_target(const DisasmLine& line) {
    if (line.target_address != INVALID_ADDRESS) {
        goto_address(line.target_address);
    }
}

void DisasmView::render_comment(const std::string& comment) {
    ImGui::TextColored(ImColor(config_.color_comment).Value, "; %s", comment.c_str());
}

void DisasmView::render_xrefs(Address address) {
    if (!config_.show_xrefs) return;

    auto refs = app_->xrefs().get_refs_to(address);
    if (refs.empty()) {
        ImGui::TextColored(ImColor(config_.color_comment).Value, "      ");
        return;
    }

    ImGui::TextColored(ImColor(config_.color_comment).Value, "[%3zu] ", refs.size());
}

void DisasmView::render_context_menu() {
    if (ImGui::BeginPopupContextWindow()) {
        if (selected_address_ != INVALID_ADDRESS) {
            ImGui::Text("Address: 0x%llX", selected_address_);
            ImGui::Separator();

            if (ImGui::MenuItem("Copy Address")) {
                auto addr_str = std::format("0x{:016X}", selected_address_);
                ImGui::SetClipboardText(addr_str.c_str());
            }

            if (ImGui::MenuItem("Go to Address...")) {
                // TODO: Open goto dialog
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Show XRefs to")) {
                // TODO: Show xref list
            }

            if (ImGui::MenuItem("Show XRefs from")) {
                // TODO: Show xref list
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Create Function")) {
                // TODO: Create function at address
            }

            if (ImGui::MenuItem("Add Comment")) {
                // TODO: Add comment dialog
            }

            if (ImGui::MenuItem("Rename...")) {
                // TODO: Rename symbol dialog
            }

#ifdef PICANHA_ENABLE_LLVM
            ImGui::Separator();
            bool can_lift = app_->has_lifting_service();
            if (ImGui::MenuItem("Lift to IR", "L", false, can_lift)) {
                app_->lift_current_function();
            }
#endif
        }
        ImGui::EndPopup();
    }
}

void DisasmView::handle_keyboard() {
    if (!ImGui::IsWindowFocused()) return;

    ImGuiIO& io = ImGui::GetIO();

    // Navigation
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
        if (selected_line_ > 0) {
            select_line(selected_line_ - 1);
            scroll_to_selection_ = true;
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
        if (selected_line_ < lines_.size() - 1) {
            select_line(selected_line_ + 1);
            scroll_to_selection_ = true;
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) {
        std::size_t page_size = 20;
        select_line(selected_line_ > page_size ? selected_line_ - page_size : 0);
        scroll_to_selection_ = true;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
        std::size_t page_size = 20;
        select_line(std::min(selected_line_ + page_size, lines_.size() - 1));
        scroll_to_selection_ = true;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Home) && io.KeyCtrl) {
        select_line(0);
        scroll_to_selection_ = true;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_End) && io.KeyCtrl) {
        if (!lines_.empty()) {
            select_line(lines_.size() - 1);
            scroll_to_selection_ = true;
        }
    }

    // Go to address
    if (ImGui::IsKeyPressed(ImGuiKey_G)) {
        // TODO: Open goto dialog
    }

    // Enter to follow jump/call
    if (ImGui::IsKeyPressed(ImGuiKey_Enter)) {
        if (selected_line_ < lines_.size()) {
            navigate_to_target(lines_[selected_line_]);
        }
    }

    // X to show xrefs popup (like IDA)
    if (ImGui::IsKeyPressed(ImGuiKey_X)) {
        if (selected_address_ != INVALID_ADDRESS) {
            // Collect all xrefs TO this address
            xref_popup_refs_ = app_->xrefs().get_refs_to(selected_address_);

            // If no incoming refs, try outgoing refs
            if (xref_popup_refs_.empty()) {
                xref_popup_refs_ = app_->xrefs().get_refs_from(selected_address_);
            }

            if (!xref_popup_refs_.empty()) {
                show_xref_popup_ = true;
                xref_nav_address_ = selected_address_;
                ImGui::OpenPopup("XRefs");
            }
        }
    }

    // Escape to go back
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        app_->navigate_back();
    }

#ifdef PICANHA_ENABLE_LLVM
    // L to lift current function
    if (ImGui::IsKeyPressed(ImGuiKey_L) && !ImGui::GetIO().WantTextInput) {
        app_->lift_current_function();
    }
#endif
}

void DisasmView::ensure_visible(Address address) {
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        if (lines_[i].address == address) {
            selected_line_ = i;
            scroll_to_selection_ = true;
            return;
        }
    }
}

void DisasmView::update_scroll() {
    // Implemented in render via scroll_to_selection_
}

std::string DisasmView::format_address(Address address) const {
    if (config_.address_width == 8) {
        return std::format("{:08X}", static_cast<std::uint32_t>(address));
    }
    return std::format("{:016X}", address);
}

std::string DisasmView::format_operand(const Instruction& instr, int operand_index) const {
    (void)instr;
    (void)operand_index;
    // Simplified - in full implementation would parse operand parts
    return "";
}

void DisasmView::calculate_flow_arrows() {
    flow_arrows_.clear();

    // Find current function bounds (if any)
    Address func_start = INVALID_ADDRESS;
    Address func_end = INVALID_ADDRESS;

    // Determine which function we're viewing based on the first instruction
    for (const auto& line : lines_) {
        if (line.type == DisasmLineType::FunctionHeader) {
            // Find this function in the function list
            for (const auto& func : app_->functions()) {
                if (func.start_address() == line.address ||
                    (!line.label.empty() && line.label.find(func.name()) != std::string::npos)) {
                    func_start = func.start_address();
                    func_end = func.end_address();
                    break;
                }
            }
            break;
        }
        if (line.type == DisasmLineType::Instruction && line.address != INVALID_ADDRESS) {
            // Find which function contains this address
            for (const auto& func : app_->functions()) {
                if (line.address >= func.start_address() && line.address < func.end_address()) {
                    func_start = func.start_address();
                    func_end = func.end_address();
                    break;
                }
            }
            break;
        }
    }

    // Collect all intra-function jumps
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        const auto& line = lines_[i];
        if (line.type != DisasmLineType::Instruction) continue;
        if (!line.is_jump) continue;
        if (line.target_address == INVALID_ADDRESS) continue;

        // Check if target is within the same function (or within view if no function)
        bool is_intra_function = false;
        if (func_start != INVALID_ADDRESS && func_end != INVALID_ADDRESS) {
            is_intra_function = (line.target_address >= func_start && line.target_address < func_end);
        } else {
            // No function context - check if target is in view
            is_intra_function = address_to_line_.contains(line.target_address);
        }

        if (!is_intra_function) continue;

        // Find target line
        auto it = address_to_line_.find(line.target_address);
        if (it == address_to_line_.end()) continue;

        std::size_t target_line = it->second;
        if (target_line == i) continue;  // Skip self-loops

        FlowArrow arrow;
        arrow.from_line = i;
        arrow.to_line = target_line;
        arrow.is_forward = (target_line > i);
        arrow.depth = 0;  // Will be calculated

        // Check if conditional (jcc vs jmp)
        // Simple heuristic: unconditional jump mnemonic starts with "jmp"
        arrow.is_conditional = (line.mnemonic != "jmp");

        flow_arrows_.push_back(arrow);
    }

    // Calculate depths to avoid overlapping arrows
    // Sort by span size (smaller spans get lower depth = closer to code)
    std::sort(flow_arrows_.begin(), flow_arrows_.end(), [](const FlowArrow& a, const FlowArrow& b) {
        std::size_t span_a = (a.from_line > a.to_line) ? (a.from_line - a.to_line) : (a.to_line - a.from_line);
        std::size_t span_b = (b.from_line > b.to_line) ? (b.from_line - b.to_line) : (b.to_line - b.from_line);
        return span_a < span_b;
    });

    // Assign depths
    for (std::size_t i = 0; i < flow_arrows_.size(); ++i) {
        flow_arrows_[i].depth = calculate_arrow_depth(flow_arrows_[i], flow_arrows_);
    }
}

int DisasmView::calculate_arrow_depth(const FlowArrow& arrow, const std::vector<FlowArrow>& arrows) {
    std::size_t min_line = std::min(arrow.from_line, arrow.to_line);
    std::size_t max_line = std::max(arrow.from_line, arrow.to_line);

    int max_depth = 0;

    // Check all previously assigned arrows for overlap
    for (const auto& other : arrows) {
        if (&other == &arrow) break;  // Only check arrows before this one

        std::size_t other_min = std::min(other.from_line, other.to_line);
        std::size_t other_max = std::max(other.from_line, other.to_line);

        // Check if ranges overlap
        bool overlaps = !(max_line < other_min || min_line > other_max);
        if (overlaps) {
            max_depth = std::max(max_depth, other.depth + 1);
        }
    }

    return max_depth;
}

void DisasmView::render_flow_arrows(std::size_t first_visible, std::size_t last_visible, float line_height) {
    if (flow_arrows_.empty()) return;

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 window_pos = ImGui::GetWindowPos();
    float scroll_y = ImGui::GetScrollY();
    float margin_width = config_.flow_arrow_margin;
    float arrow_spacing = 8.0f;  // Space between nested arrows
    float half_line = line_height / 2.0f;

    for (const auto& arrow : flow_arrows_) {
        // Skip if arrow is completely outside visible range
        std::size_t min_line = std::min(arrow.from_line, arrow.to_line);
        std::size_t max_line = std::max(arrow.from_line, arrow.to_line);

        if (max_line < first_visible || min_line > last_visible) continue;

        // Calculate positions
        float from_y = window_pos.y + (arrow.from_line * line_height) - scroll_y + half_line;
        float to_y = window_pos.y + (arrow.to_line * line_height) - scroll_y + half_line;

        // X position based on depth (deeper = further left)
        float x = window_pos.x + margin_width - (arrow.depth + 1) * arrow_spacing;

        // Clamp to margin bounds
        x = std::max(window_pos.x + 4.0f, x);

        // Choose color based on direction
        ImU32 color = arrow.is_forward ? config_.color_flow_arrow : config_.color_flow_arrow_back;

        // Make conditional jumps slightly more transparent
        if (arrow.is_conditional) {
            ImU32 alpha = (color >> 24) & 0xFF;
            alpha = static_cast<ImU32>(alpha * 0.7f);
            color = (color & 0x00FFFFFF) | (alpha << 24);
        }

        float thickness = 1.5f;

        // Draw the arrow: vertical line + horizontal ticks + arrow head
        // Vertical line
        draw_list->AddLine(ImVec2(x, from_y), ImVec2(x, to_y), color, thickness);

        // Horizontal tick at source (from_line)
        float tick_len = 4.0f;
        draw_list->AddLine(ImVec2(x, from_y), ImVec2(x + tick_len, from_y), color, thickness);

        // Horizontal tick at target with arrow head
        draw_list->AddLine(ImVec2(x, to_y), ImVec2(x + tick_len + 4.0f, to_y), color, thickness);

        // Arrow head pointing right at target
        float arrow_size = 4.0f;
        ImVec2 arrow_tip(x + tick_len + 4.0f, to_y);
        draw_list->AddTriangleFilled(
            arrow_tip,
            ImVec2(arrow_tip.x - arrow_size, arrow_tip.y - arrow_size / 2),
            ImVec2(arrow_tip.x - arrow_size, arrow_tip.y + arrow_size / 2),
            color
        );
    }
}

} // namespace picanha::ui
