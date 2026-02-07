#pragma once

#include "picanha/persistence/schema.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <sqlite3.h>
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <optional>

namespace picanha::persistence {

// Forward declarations
class Database;
class Statement;
class Transaction;

// SQLite statement wrapper (RAII)
class Statement {
public:
    Statement() = default;
    Statement(sqlite3_stmt* stmt) : stmt_(stmt) {}
    ~Statement();

    Statement(Statement&& other) noexcept;
    Statement& operator=(Statement&& other) noexcept;

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    // Binding parameters
    bool bind(int index, int value);
    bool bind(int index, std::int64_t value);
    bool bind(int index, double value);
    bool bind(int index, const std::string& value);
    bool bind(int index, std::string_view value);
    bool bind(int index, const void* data, std::size_t size);
    bool bind_null(int index);

    // Named parameter binding
    bool bind(const char* name, int value);
    bool bind(const char* name, std::int64_t value);
    bool bind(const char* name, const std::string& value);

    // Execution
    bool step();                    // Execute one step, returns true if row available
    bool execute();                 // Execute until done
    void reset();                   // Reset for re-execution

    // Column access
    [[nodiscard]] int column_count() const;
    [[nodiscard]] int column_int(int col) const;
    [[nodiscard]] std::int64_t column_int64(int col) const;
    [[nodiscard]] double column_double(int col) const;
    [[nodiscard]] std::string column_text(int col) const;
    [[nodiscard]] std::string_view column_text_view(int col) const;
    [[nodiscard]] const void* column_blob(int col) const;
    [[nodiscard]] int column_bytes(int col) const;
    [[nodiscard]] bool column_is_null(int col) const;

    // Check validity
    [[nodiscard]] bool is_valid() const { return stmt_ != nullptr; }
    [[nodiscard]] sqlite3_stmt* handle() const { return stmt_; }

private:
    sqlite3_stmt* stmt_{nullptr};
};

// Transaction wrapper (RAII)
class Transaction {
public:
    explicit Transaction(Database& db);
    ~Transaction();

    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    void commit();
    void rollback();

private:
    Database& db_;
    bool committed_{false};
    bool rolled_back_{false};
};

// Database manager
class Database {
public:
    Database() = default;
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Open/close
    [[nodiscard]] Result<void> open(const std::string& path);
    [[nodiscard]] Result<void> create(const std::string& path);
    void close();

    [[nodiscard]] bool is_open() const { return db_ != nullptr; }
    [[nodiscard]] const std::string& path() const { return path_; }

    // Schema management
    [[nodiscard]] Result<void> create_schema();
    [[nodiscard]] Result<std::uint32_t> get_schema_version();
    [[nodiscard]] Result<void> migrate_schema(std::uint32_t from_version);

    // Statement preparation
    [[nodiscard]] Result<Statement> prepare(std::string_view sql);

    // Direct execution
    [[nodiscard]] Result<void> execute(std::string_view sql);
    [[nodiscard]] Result<void> execute(const Statement& stmt);

    // Transaction support
    [[nodiscard]] Result<void> begin_transaction();
    [[nodiscard]] Result<void> commit();
    [[nodiscard]] Result<void> rollback();

    // Utility
    [[nodiscard]] std::int64_t last_insert_rowid() const;
    [[nodiscard]] int changes() const;
    [[nodiscard]] const char* last_error() const;

    // Query helpers
    template<typename T>
    [[nodiscard]] std::optional<T> query_scalar(std::string_view sql);

    // Iteration helpers
    using RowCallback = std::function<bool(Statement&)>;  // Return false to stop
    [[nodiscard]] Result<void> query(std::string_view sql, RowCallback callback);

    // Get raw handle (for advanced use)
    [[nodiscard]] sqlite3* handle() const { return db_; }

private:
    sqlite3* db_{nullptr};
    std::string path_;
};

// Template implementations
template<typename T>
std::optional<T> Database::query_scalar(std::string_view sql) {
    auto stmt_result = prepare(sql);
    if (!stmt_result) return std::nullopt;

    auto& stmt = *stmt_result;
    if (!stmt.step()) return std::nullopt;

    if constexpr (std::is_same_v<T, int>) {
        return stmt.column_int(0);
    } else if constexpr (std::is_same_v<T, std::int64_t>) {
        return stmt.column_int64(0);
    } else if constexpr (std::is_same_v<T, double>) {
        return stmt.column_double(0);
    } else if constexpr (std::is_same_v<T, std::string>) {
        return stmt.column_text(0);
    } else {
        static_assert(sizeof(T) == 0, "Unsupported type for query_scalar");
    }
}

} // namespace picanha::persistence
