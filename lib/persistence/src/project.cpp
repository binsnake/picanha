#include "picanha/persistence/project.hpp"
#include <picanha/core/hash.hpp>
#include <spdlog/spdlog.h>
#include <fstream>
#include <chrono>

namespace picanha::persistence {

namespace {

std::int64_t to_timestamp(std::chrono::system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(
        tp.time_since_epoch()
    ).count();
}

std::chrono::system_clock::time_point from_timestamp(std::int64_t ts) {
    return std::chrono::system_clock::time_point(std::chrono::seconds(ts));
}

} // anonymous namespace

Project::Project() = default;
Project::~Project() {
    close();
}

Result<void> Project::create(
    const std::filesystem::path& path,
    const std::string& name
) {
    auto result = db_.create(path.string());
    if (!result) return result;

    path_ = path;
    info_.name = name;
    info_.created_at = std::chrono::system_clock::now();
    info_.modified_at = info_.created_at;
    info_.schema_version = SCHEMA_VERSION;

    return save_info();
}

Result<void> Project::open(const std::filesystem::path& path) {
    auto result = db_.open(path.string());
    if (!result) return result;

    path_ = path;

    // Check schema version
    auto version_result = db_.get_schema_version();
    if (!version_result) {
        // Old database without version, try to migrate
        auto migrate_result = db_.create_schema();
        if (!migrate_result) return migrate_result;
    } else if (*version_result < SCHEMA_VERSION) {
        auto migrate_result = db_.migrate_schema(*version_result);
        if (!migrate_result) return migrate_result;
    }

    return load_info();
}

Result<void> Project::save() {
    if (!is_open()) {
        return std::unexpected(internal_error("No project open"));
    }

    info_.modified_at = std::chrono::system_clock::now();
    auto result = save_info();
    if (!result) return result;

    modified_ = false;
    return {};
}

Result<void> Project::save_as(const std::filesystem::path& path) {
    // Close current database
    auto old_path = path_;
    close();

    // Copy file if different path
    if (path != old_path && std::filesystem::exists(old_path)) {
        try {
            std::filesystem::copy_file(old_path, path,
                std::filesystem::copy_options::overwrite_existing);
        } catch (const std::exception& e) {
            return std::unexpected(io_error(e.what()));
        }
    }

    // Open new location
    auto result = db_.open(path.string());
    if (!result) return result;

    path_ = path;
    return save();
}

void Project::close() {
    if (is_open()) {
        db_.close();
        path_.clear();
        info_ = ProjectInfo{};
        binary_.reset();
        modified_ = false;
    }
}

void Project::set_name(const std::string& name) {
    info_.name = name;
    modified_ = true;
}

void Project::set_description(const std::string& description) {
    info_.description = description;
    modified_ = true;
}

Result<void> Project::set_binary(std::shared_ptr<loader::Binary> binary) {
    binary_ = std::move(binary);

    if (binary_) {
        info_.image_base = binary_->image_base();
        info_.entry_point = binary_->entry_point();
        info_.binary_hash = compute_binary_hash();
    }

    modified_ = true;
    return save_info();
}

Result<void> Project::save_functions(
    const std::vector<analysis::Function>& functions,
    ProjectProgressCallback callback
) {
    Transaction txn(db_);

    // Clear existing
    auto result = db_.execute("DELETE FROM block_edges");
    if (!result) return result;
    result = db_.execute("DELETE FROM blocks");
    if (!result) return result;
    result = db_.execute("DELETE FROM functions");
    if (!result) return result;

    // Prepare statements
    auto func_stmt = db_.prepare(R"(
        INSERT INTO functions (id, entry_address, name, type, calling_conv, flags,
                               stack_frame_size, local_vars_size, args_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )");
    if (!func_stmt) return std::unexpected(func_stmt.error());

    auto block_stmt = db_.prepare(R"(
        INSERT INTO blocks (id, function_id, start_address, end_address,
                           is_entry, is_exit, has_call, has_indirect, idom_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )");
    if (!block_stmt) return std::unexpected(block_stmt.error());

    auto edge_stmt = db_.prepare(R"(
        INSERT INTO block_edges (from_block_id, to_block_id, edge_type, is_back_edge)
        VALUES (?, ?, ?, ?)
    )");
    if (!edge_stmt) return std::unexpected(edge_stmt.error());

    std::size_t total = functions.size();
    std::size_t processed = 0;
    std::int64_t global_block_id = 0;

    for (const auto& func : functions) {
        // Insert function
        func_stmt->reset();
        func_stmt->bind(1, static_cast<std::int64_t>(func.id()));
        func_stmt->bind(2, static_cast<std::int64_t>(func.entry_address()));
        func_stmt->bind(3, func.name());
        func_stmt->bind(4, static_cast<int>(func.type()));
        func_stmt->bind(5, static_cast<int>(func.calling_convention()));
        func_stmt->bind(6, static_cast<int>(func.flags()));
        func_stmt->bind(7, func.stack_frame_size());
        func_stmt->bind(8, func.local_vars_size());
        func_stmt->bind(9, func.args_size());

        if (!func_stmt->execute()) {
            return std::unexpected(database_error("Failed to insert function"));
        }

        // Insert blocks
        std::unordered_map<BlockId, std::int64_t> block_id_map;

        func.cfg().for_each_block([&](const analysis::BasicBlock& block) {
            std::int64_t db_block_id = ++global_block_id;
            block_id_map[block.id()] = db_block_id;

            block_stmt->reset();
            block_stmt->bind(1, db_block_id);
            block_stmt->bind(2, static_cast<std::int64_t>(func.id()));
            block_stmt->bind(3, static_cast<std::int64_t>(block.start_address()));
            block_stmt->bind(4, static_cast<std::int64_t>(block.end_address()));
            block_stmt->bind(5, block.is_entry_block() ? 1 : 0);
            block_stmt->bind(6, block.is_exit_block() ? 1 : 0);
            block_stmt->bind(7, block.has_call() ? 1 : 0);
            block_stmt->bind(8, block.has_indirect() ? 1 : 0);

            if (block.immediate_dominator() != INVALID_BLOCK_ID) {
                // Will need to update after all blocks inserted
                block_stmt->bind_null(9);
            } else {
                block_stmt->bind_null(9);
            }

            block_stmt->execute();
        });

        // Insert edges
        func.cfg().for_each_block([&](const analysis::BasicBlock& block) {
            auto from_it = block_id_map.find(block.id());
            if (from_it == block_id_map.end()) return;

            for (const auto& edge : block.successors()) {
                auto to_it = block_id_map.find(edge.target);
                if (to_it == block_id_map.end()) continue;

                edge_stmt->reset();
                edge_stmt->bind(1, from_it->second);
                edge_stmt->bind(2, to_it->second);
                edge_stmt->bind(3, static_cast<int>(edge.type));
                edge_stmt->bind(4, edge.is_back_edge ? 1 : 0);
                edge_stmt->execute();
            }
        });

        ++processed;
        if (callback) {
            callback(static_cast<float>(processed) / static_cast<float>(total),
                     "Saving functions...");
        }
    }

    txn.commit();
    modified_ = true;
    return {};
}

Result<std::vector<analysis::Function>> Project::load_functions(
    ProjectProgressCallback callback
) {
    std::vector<analysis::Function> functions;

    // Count functions
    auto count = db_.query_scalar<std::int64_t>("SELECT COUNT(*) FROM functions");
    std::size_t total = count.value_or(0);
    std::size_t processed = 0;

    // Load functions
    auto result = db_.query(
        "SELECT id, entry_address, name, type, calling_conv, flags, "
        "stack_frame_size, local_vars_size, args_size FROM functions",
        [&](Statement& stmt) {
            analysis::Function func(
                static_cast<FunctionId>(stmt.column_int64(0)),
                static_cast<Address>(stmt.column_int64(1))
            );

            func.set_name(stmt.column_text(2));
            func.set_type(static_cast<analysis::FunctionType>(stmt.column_int(3)));
            func.set_calling_convention(
                static_cast<analysis::CallingConvention>(stmt.column_int(4)));

            // Load flags
            auto flags = static_cast<analysis::FunctionFlags>(stmt.column_int(5));
            if (picanha::has_flag(flags, analysis::FunctionFlags::HasVarArgs))
                func.set_flag(analysis::FunctionFlags::HasVarArgs);
            // ... other flags

            func.set_stack_frame_size(stmt.column_int(6));
            func.set_local_vars_size(stmt.column_int(7));
            func.set_args_size(stmt.column_int(8));

            functions.push_back(std::move(func));

            ++processed;
            if (callback) {
                callback(static_cast<float>(processed) / static_cast<float>(total),
                         "Loading functions...");
            }

            return true;
        }
    );

    if (!result) return std::unexpected(result.error());

    // TODO: Load blocks and edges for each function's CFG

    return functions;
}

Result<void> Project::save_symbols(
    const analysis::SymbolTable& symbols,
    ProjectProgressCallback callback
) {
    Transaction txn(db_);

    auto result = db_.execute("DELETE FROM symbols");
    if (!result) return result;

    auto stmt = db_.prepare(R"(
        INSERT INTO symbols (id, address, size, name, demangled_name, module_name,
                            type, visibility, source, flags, function_id, ordinal)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )");
    if (!stmt) return std::unexpected(stmt.error());

    std::size_t total = symbols.count();
    std::size_t processed = 0;

    symbols.for_each([&](const analysis::Symbol& sym) {
        stmt->reset();
        stmt->bind(1, static_cast<std::int64_t>(sym.id));
        stmt->bind(2, static_cast<std::int64_t>(sym.address));
        stmt->bind(3, static_cast<std::int64_t>(sym.size));
        stmt->bind(4, sym.name);
        stmt->bind(5, sym.demangled_name);
        stmt->bind(6, sym.module_name);
        stmt->bind(7, static_cast<int>(sym.type));
        stmt->bind(8, static_cast<int>(sym.visibility));
        stmt->bind(9, static_cast<int>(sym.source));
        stmt->bind(10, static_cast<int>(sym.flags));

        if (sym.function_id != INVALID_FUNCTION_ID) {
            stmt->bind(11, static_cast<std::int64_t>(sym.function_id));
        } else {
            stmt->bind_null(11);
        }

        stmt->bind(12, static_cast<int>(sym.ordinal));
        stmt->execute();

        ++processed;
        if (callback) {
            callback(static_cast<float>(processed) / static_cast<float>(total),
                     "Saving symbols...");
        }
    });

    txn.commit();
    modified_ = true;
    return {};
}

Result<void> Project::load_symbols(
    analysis::SymbolTable& symbols,
    ProjectProgressCallback callback
) {
    auto count = db_.query_scalar<std::int64_t>("SELECT COUNT(*) FROM symbols");
    std::size_t total = count.value_or(0);
    std::size_t processed = 0;

    auto result = db_.query(
        "SELECT id, address, size, name, demangled_name, module_name, "
        "type, visibility, source, flags, function_id, ordinal FROM symbols",
        [&](Statement& stmt) {
            analysis::Symbol sym;
            sym.id = static_cast<analysis::SymbolId>(stmt.column_int64(0));
            sym.address = static_cast<Address>(stmt.column_int64(1));
            sym.size = static_cast<Size>(stmt.column_int64(2));
            sym.name = stmt.column_text(3);
            sym.demangled_name = stmt.column_text(4);
            sym.module_name = stmt.column_text(5);
            sym.type = static_cast<analysis::SymbolType>(stmt.column_int(6));
            sym.visibility = static_cast<analysis::SymbolVisibility>(stmt.column_int(7));
            sym.source = static_cast<analysis::SymbolSource>(stmt.column_int(8));
            sym.flags = static_cast<analysis::SymbolFlags>(stmt.column_int(9));

            if (!stmt.column_is_null(10)) {
                sym.function_id = static_cast<FunctionId>(stmt.column_int64(10));
            }

            sym.ordinal = static_cast<std::uint16_t>(stmt.column_int(11));

            symbols.add(std::move(sym));

            ++processed;
            if (callback) {
                callback(static_cast<float>(processed) / static_cast<float>(total),
                         "Loading symbols...");
            }

            return true;
        }
    );

    return result;
}

Result<void> Project::save_xrefs(
    const analysis::XRefManager& xrefs,
    ProjectProgressCallback callback
) {
    Transaction txn(db_);

    auto result = db_.execute("DELETE FROM xrefs");
    if (!result) return result;

    auto stmt = db_.prepare(R"(
        INSERT INTO xrefs (from_address, to_address, type, flow,
                          from_func_id, to_func_id, from_block_id, to_block_id,
                          is_user_defined, is_indirect, is_conditional)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )");
    if (!stmt) return std::unexpected(stmt.error());

    std::size_t total = xrefs.count();
    std::size_t processed = 0;

    xrefs.for_each([&](const analysis::XRef& xref) {
        stmt->reset();
        stmt->bind(1, static_cast<std::int64_t>(xref.from));
        stmt->bind(2, static_cast<std::int64_t>(xref.to));
        stmt->bind(3, static_cast<int>(xref.type));
        stmt->bind(4, static_cast<int>(xref.flow));

        if (xref.from_func != INVALID_FUNCTION_ID) {
            stmt->bind(5, static_cast<std::int64_t>(xref.from_func));
        } else {
            stmt->bind_null(5);
        }

        if (xref.to_func != INVALID_FUNCTION_ID) {
            stmt->bind(6, static_cast<std::int64_t>(xref.to_func));
        } else {
            stmt->bind_null(6);
        }

        if (xref.from_block != INVALID_BLOCK_ID) {
            stmt->bind(7, static_cast<std::int64_t>(xref.from_block));
        } else {
            stmt->bind_null(7);
        }

        if (xref.to_block != INVALID_BLOCK_ID) {
            stmt->bind(8, static_cast<std::int64_t>(xref.to_block));
        } else {
            stmt->bind_null(8);
        }

        stmt->bind(9, xref.is_user_defined ? 1 : 0);
        stmt->bind(10, xref.is_indirect ? 1 : 0);
        stmt->bind(11, xref.is_conditional ? 1 : 0);
        stmt->execute();

        ++processed;
        if (callback) {
            callback(static_cast<float>(processed) / static_cast<float>(total),
                     "Saving xrefs...");
        }
    });

    txn.commit();
    modified_ = true;
    return {};
}

Result<void> Project::load_xrefs(
    analysis::XRefManager& xrefs,
    ProjectProgressCallback callback
) {
    auto count = db_.query_scalar<std::int64_t>("SELECT COUNT(*) FROM xrefs");
    std::size_t total = count.value_or(0);
    std::size_t processed = 0;

    auto result = db_.query(
        "SELECT from_address, to_address, type, flow, "
        "from_func_id, to_func_id, from_block_id, to_block_id, "
        "is_user_defined, is_indirect, is_conditional FROM xrefs",
        [&](Statement& stmt) {
            analysis::XRef xref;
            xref.from = static_cast<Address>(stmt.column_int64(0));
            xref.to = static_cast<Address>(stmt.column_int64(1));
            xref.type = static_cast<analysis::XRefType>(stmt.column_int(2));
            xref.flow = static_cast<analysis::XRefFlow>(stmt.column_int(3));

            if (!stmt.column_is_null(4))
                xref.from_func = static_cast<FunctionId>(stmt.column_int64(4));
            if (!stmt.column_is_null(5))
                xref.to_func = static_cast<FunctionId>(stmt.column_int64(5));
            if (!stmt.column_is_null(6))
                xref.from_block = static_cast<BlockId>(stmt.column_int64(6));
            if (!stmt.column_is_null(7))
                xref.to_block = static_cast<BlockId>(stmt.column_int64(7));

            xref.is_user_defined = stmt.column_int(8) != 0;
            xref.is_indirect = stmt.column_int(9) != 0;
            xref.is_conditional = stmt.column_int(10) != 0;

            xrefs.add(xref);

            ++processed;
            if (callback) {
                callback(static_cast<float>(processed) / static_cast<float>(total),
                         "Loading xrefs...");
            }

            return true;
        }
    );

    return result;
}

Result<void> Project::save_jump_tables(
    const std::vector<analysis::JumpTable>& tables
) {
    Transaction txn(db_);

    auto result = db_.execute("DELETE FROM jump_table_entries");
    if (!result) return result;
    result = db_.execute("DELETE FROM jump_tables");
    if (!result) return result;

    auto table_stmt = db_.prepare(R"(
        INSERT INTO jump_tables (table_address, instruction_address, base_address,
                                 entry_count, entry_size, entry_type, confidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )");
    if (!table_stmt) return std::unexpected(table_stmt.error());

    auto entry_stmt = db_.prepare(R"(
        INSERT INTO jump_table_entries (table_id, index_value, target_address)
        VALUES (?, ?, ?)
    )");
    if (!entry_stmt) return std::unexpected(entry_stmt.error());

    for (const auto& table : tables) {
        table_stmt->reset();
        table_stmt->bind(1, static_cast<std::int64_t>(table.table_address));
        table_stmt->bind(2, static_cast<std::int64_t>(table.instruction_address));
        table_stmt->bind(3, static_cast<std::int64_t>(table.base_address));
        table_stmt->bind(4, static_cast<std::int64_t>(table.entry_count));
        table_stmt->bind(5, static_cast<std::int64_t>(table.entry_size));
        table_stmt->bind(6, static_cast<int>(table.entry_type));
        table_stmt->bind(7, static_cast<int>(table.confidence));
        table_stmt->execute();

        std::int64_t table_id = db_.last_insert_rowid();

        for (std::size_t i = 0; i < table.targets.size(); ++i) {
            entry_stmt->reset();
            entry_stmt->bind(1, table_id);
            entry_stmt->bind(2, static_cast<std::int64_t>(i));
            entry_stmt->bind(3, static_cast<std::int64_t>(table.targets[i]));
            entry_stmt->execute();
        }
    }

    txn.commit();
    modified_ = true;
    return {};
}

Result<std::vector<analysis::JumpTable>> Project::load_jump_tables() {
    std::vector<analysis::JumpTable> tables;

    auto result = db_.query(
        "SELECT id, table_address, instruction_address, base_address, "
        "entry_count, entry_size, entry_type, confidence FROM jump_tables",
        [&](Statement& stmt) {
            analysis::JumpTable table;
            std::int64_t table_id = stmt.column_int64(0);
            table.table_address = static_cast<Address>(stmt.column_int64(1));
            table.instruction_address = static_cast<Address>(stmt.column_int64(2));
            table.base_address = static_cast<Address>(stmt.column_int64(3));
            table.entry_count = static_cast<std::size_t>(stmt.column_int64(4));
            table.entry_size = static_cast<std::size_t>(stmt.column_int64(5));
            table.entry_type = static_cast<analysis::JumpTableEntryType>(stmt.column_int(6));
            table.confidence = static_cast<std::uint8_t>(stmt.column_int(7));

            // Load entries
            auto entry_stmt = db_.prepare(
                "SELECT target_address FROM jump_table_entries "
                "WHERE table_id = ? ORDER BY index_value"
            );
            if (entry_stmt) {
                entry_stmt->bind(1, table_id);
                while (entry_stmt->step()) {
                    table.targets.push_back(
                        static_cast<Address>(entry_stmt->column_int64(0))
                    );
                }
            }

            tables.push_back(std::move(table));
            return true;
        }
    );

    if (!result) return std::unexpected(result.error());
    return tables;
}

Result<void> Project::add_comment(const Comment& comment) {
    auto stmt = db_.prepare(R"(
        INSERT OR REPLACE INTO comments (address, type, text, created_at, modified_at)
        VALUES (?, ?, ?, ?, ?)
    )");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, static_cast<std::int64_t>(comment.address));
    stmt->bind(2, static_cast<int>(comment.type));
    stmt->bind(3, comment.text);
    stmt->bind(4, to_timestamp(comment.created_at));
    stmt->bind(5, to_timestamp(comment.modified_at));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to insert comment"));
    }

    modified_ = true;
    return {};
}

Result<void> Project::update_comment(Address address, const std::string& text) {
    auto stmt = db_.prepare(
        "UPDATE comments SET text = ?, modified_at = ? WHERE address = ?"
    );
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, text);
    stmt->bind(2, to_timestamp(std::chrono::system_clock::now()));
    stmt->bind(3, static_cast<std::int64_t>(address));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to update comment"));
    }

    modified_ = true;
    return {};
}

Result<void> Project::delete_comment(Address address) {
    auto stmt = db_.prepare("DELETE FROM comments WHERE address = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, static_cast<std::int64_t>(address));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to delete comment"));
    }

    modified_ = true;
    return {};
}

Result<std::optional<Comment>> Project::get_comment(Address address) {
    auto stmt = db_.prepare(
        "SELECT type, text, created_at, modified_at FROM comments WHERE address = ?"
    );
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, static_cast<std::int64_t>(address));

    if (!stmt->step()) {
        return std::nullopt;
    }

    Comment comment;
    comment.address = address;
    comment.type = static_cast<CommentType>(stmt->column_int(0));
    comment.text = stmt->column_text(1);
    comment.created_at = from_timestamp(stmt->column_int64(2));
    comment.modified_at = from_timestamp(stmt->column_int64(3));

    return comment;
}

Result<std::vector<Comment>> Project::get_all_comments() {
    std::vector<Comment> comments;

    auto result = db_.query(
        "SELECT address, type, text, created_at, modified_at FROM comments",
        [&](Statement& stmt) {
            Comment comment;
            comment.address = static_cast<Address>(stmt.column_int64(0));
            comment.type = static_cast<CommentType>(stmt.column_int(1));
            comment.text = stmt.column_text(2);
            comment.created_at = from_timestamp(stmt.column_int64(3));
            comment.modified_at = from_timestamp(stmt.column_int64(4));
            comments.push_back(std::move(comment));
            return true;
        }
    );

    if (!result) return std::unexpected(result.error());
    return comments;
}

Result<void> Project::add_bookmark(const Bookmark& bookmark) {
    auto stmt = db_.prepare(R"(
        INSERT INTO bookmarks (address, name, description, color, created_at)
        VALUES (?, ?, ?, ?, ?)
    )");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, static_cast<std::int64_t>(bookmark.address));
    stmt->bind(2, bookmark.name);
    stmt->bind(3, bookmark.description);
    stmt->bind(4, static_cast<int>(bookmark.color));
    stmt->bind(5, to_timestamp(bookmark.created_at));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to insert bookmark"));
    }

    modified_ = true;
    return {};
}

Result<void> Project::delete_bookmark(Address address) {
    auto stmt = db_.prepare("DELETE FROM bookmarks WHERE address = ?");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, static_cast<std::int64_t>(address));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to delete bookmark"));
    }

    modified_ = true;
    return {};
}

Result<std::vector<Bookmark>> Project::get_all_bookmarks() {
    std::vector<Bookmark> bookmarks;

    auto result = db_.query(
        "SELECT address, name, description, color, created_at FROM bookmarks",
        [&](Statement& stmt) {
            Bookmark bookmark;
            bookmark.address = static_cast<Address>(stmt.column_int64(0));
            bookmark.name = stmt.column_text(1);
            bookmark.description = stmt.column_text(2);
            bookmark.color = static_cast<std::uint32_t>(stmt.column_int(3));
            bookmark.created_at = from_timestamp(stmt.column_int64(4));
            bookmarks.push_back(std::move(bookmark));
            return true;
        }
    );

    if (!result) return std::unexpected(result.error());
    return bookmarks;
}

Result<void> Project::set_state(const std::string& key, const std::string& value) {
    auto stmt = db_.prepare(
        "INSERT OR REPLACE INTO analysis_state (key, value) VALUES (?, ?)"
    );
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, key);
    stmt->bind(2, value);

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to set state"));
    }

    return {};
}

Result<std::optional<std::string>> Project::get_state(const std::string& key) {
    auto stmt = db_.prepare(
        "SELECT value FROM analysis_state WHERE key = ?"
    );
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, key);

    if (!stmt->step()) {
        return std::nullopt;
    }

    return stmt->column_text(0);
}

Result<void> Project::load_info() {
    auto result = db_.query(
        "SELECT name, description, created_at, modified_at, schema_version, "
        "binary_path, binary_hash, image_base, entry_point FROM project LIMIT 1",
        [this](Statement& stmt) {
            info_.name = stmt.column_text(0);
            info_.description = stmt.column_text(1);
            info_.created_at = from_timestamp(stmt.column_int64(2));
            info_.modified_at = from_timestamp(stmt.column_int64(3));
            info_.schema_version = static_cast<std::uint32_t>(stmt.column_int(4));
            info_.binary_path = stmt.column_text(5);
            info_.binary_hash = stmt.column_text(6);
            info_.image_base = static_cast<Address>(stmt.column_int64(7));
            info_.entry_point = static_cast<Address>(stmt.column_int64(8));
            return false;  // Only one row
        }
    );

    return result;
}

Result<void> Project::save_info() {
    auto result = db_.execute("DELETE FROM project");
    if (!result) return result;

    auto stmt = db_.prepare(R"(
        INSERT INTO project (name, description, created_at, modified_at, schema_version,
                            binary_path, binary_hash, image_base, entry_point)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )");
    if (!stmt) return std::unexpected(stmt.error());

    stmt->bind(1, info_.name);
    stmt->bind(2, info_.description);
    stmt->bind(3, to_timestamp(info_.created_at));
    stmt->bind(4, to_timestamp(info_.modified_at));
    stmt->bind(5, static_cast<int>(info_.schema_version));
    stmt->bind(6, info_.binary_path);
    stmt->bind(7, info_.binary_hash);
    stmt->bind(8, static_cast<std::int64_t>(info_.image_base));
    stmt->bind(9, static_cast<std::int64_t>(info_.entry_point));

    if (!stmt->execute()) {
        return std::unexpected(database_error("Failed to save project info"));
    }

    return {};
}

std::string Project::compute_binary_hash() const {
    if (!binary_) return "";

    // Use xxHash on the binary data
    // This is a simplified implementation - would hash the actual file
    return "";  // TODO: Implement proper hash
}

std::string compute_file_hash(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

    // Read file and compute hash
    std::vector<char> buffer(64 * 1024);
    XXH64_state_t* state = XXH64_createState();
    XXH64_reset(state, 0);

    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        XXH64_update(state, buffer.data(), static_cast<size_t>(file.gcount()));
    }

    XXH64_hash_t hash = XXH64_digest(state);
    XXH64_freeState(state);

    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(hash));
    return hex;
}

} // namespace picanha::persistence
