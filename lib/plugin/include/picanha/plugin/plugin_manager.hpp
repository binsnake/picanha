#pragma once

#include "picanha/plugin/plugin.hpp"
#include "picanha/plugin/function_pass.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <functional>

namespace picanha::plugin {

// Loaded plugin handle
struct LoadedPlugin {
    std::string path;
    std::string name;
    void* handle{nullptr};          // Platform-specific module handle
    IPlugin* instance{nullptr};
    PluginCreateFunc create_func{nullptr};
    PluginDestroyFunc destroy_func{nullptr};
    bool initialized{false};
};

// Plugin discovery result
struct PluginDiscoveryResult {
    std::vector<std::filesystem::path> found_plugins;
    std::vector<std::string> errors;
};

// Plugin manager configuration
struct PluginManagerConfig {
    std::vector<std::filesystem::path> search_paths;
    bool auto_initialize{true};
    bool load_on_discovery{false};
};

// Plugin manager - handles loading, unloading, and managing plugins
class PluginManager {
public:
    explicit PluginManager(const PluginManagerConfig& config = {});
    ~PluginManager();

    // Non-copyable
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    // Discovery
    [[nodiscard]] PluginDiscoveryResult discover_plugins();
    void add_search_path(const std::filesystem::path& path);

    // Loading
    [[nodiscard]] bool load_plugin(const std::filesystem::path& path);
    [[nodiscard]] bool load_all_discovered();
    void unload_plugin(const std::string& name);
    void unload_all();

    // Initialization
    bool initialize_plugin(const std::string& name, PluginContext* context);
    bool initialize_all(PluginContext* context);
    void shutdown_all();

    // Query
    [[nodiscard]] bool is_loaded(const std::string& name) const;
    [[nodiscard]] bool is_initialized(const std::string& name) const;
    [[nodiscard]] const LoadedPlugin* get_plugin(const std::string& name) const;

    // Get plugins by type
    [[nodiscard]] std::vector<IPlugin*> get_plugins_by_type(PluginType type) const;
    [[nodiscard]] std::vector<IFunctionPass*> get_function_passes() const;

    // Iteration
    using PluginVisitor = std::function<void(const LoadedPlugin&)>;
    void for_each_plugin(PluginVisitor visitor) const;

    // Get all loaded plugin names
    [[nodiscard]] std::vector<std::string> get_loaded_names() const;

    // Statistics
    [[nodiscard]] std::size_t plugin_count() const { return plugins_.size(); }
    [[nodiscard]] std::size_t initialized_count() const;

private:
    // Platform-specific loading
    [[nodiscard]] void* load_library(const std::filesystem::path& path);
    void unload_library(void* handle);
    [[nodiscard]] void* get_symbol(void* handle, const char* name);

    // Validation
    [[nodiscard]] bool validate_plugin(const LoadedPlugin& plugin) const;

    PluginManagerConfig config_;
    std::vector<LoadedPlugin> plugins_;
    std::unordered_map<std::string, std::size_t> name_to_index_;
};

// Default plugin context implementation
class DefaultPluginContext : public PluginContext {
public:
    void log_info(const char* message) override;
    void log_warning(const char* message) override;
    void log_error(const char* message) override;

    void report_progress(float progress, const char* status) override;
    [[nodiscard]] bool is_cancelled() const override;

    [[nodiscard]] const char* app_version() const override;

    // Set cancellation
    void cancel() { cancelled_ = true; }
    void reset_cancel() { cancelled_ = false; }

    // Set progress callback
    using ProgressCallback = std::function<void(float, const char*)>;
    void set_progress_callback(ProgressCallback cb) { progress_cb_ = std::move(cb); }

    // Set log callbacks
    using LogCallback = std::function<void(const char*)>;
    void set_log_info_callback(LogCallback cb) { log_info_cb_ = std::move(cb); }
    void set_log_warning_callback(LogCallback cb) { log_warning_cb_ = std::move(cb); }
    void set_log_error_callback(LogCallback cb) { log_error_cb_ = std::move(cb); }

private:
    std::atomic<bool> cancelled_{false};
    ProgressCallback progress_cb_;
    LogCallback log_info_cb_;
    LogCallback log_warning_cb_;
    LogCallback log_error_cb_;
};

} // namespace picanha::plugin
