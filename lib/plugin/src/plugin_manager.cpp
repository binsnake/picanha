#include "picanha/plugin/plugin_manager.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

namespace picanha::plugin {

PluginManager::PluginManager(const PluginManagerConfig& config)
    : config_(config)
{}

PluginManager::~PluginManager() {
    shutdown_all();
    unload_all();
}

PluginDiscoveryResult PluginManager::discover_plugins() {
    PluginDiscoveryResult result;

#ifdef _WIN32
    const char* extension = ".dll";
#else
    const char* extension = ".so";
#endif

    for (const auto& search_path : config_.search_paths) {
        if (!std::filesystem::exists(search_path)) {
            continue;
        }

        try {
            for (const auto& entry : std::filesystem::directory_iterator(search_path)) {
                if (!entry.is_regular_file()) continue;

                auto path = entry.path();
                if (path.extension() == extension) {
                    result.found_plugins.push_back(path);

                    if (config_.load_on_discovery) {
                        if (!load_plugin(path)) {
                            result.errors.push_back(
                                "Failed to load: " + path.string()
                            );
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            result.errors.push_back(
                "Error scanning " + search_path.string() + ": " + e.what()
            );
        }
    }

    return result;
}

void PluginManager::add_search_path(const std::filesystem::path& path) {
    config_.search_paths.push_back(path);
}

bool PluginManager::load_plugin(const std::filesystem::path& path) {
    // Check if already loaded
    for (const auto& plugin : plugins_) {
        if (plugin.path == path.string()) {
            return true;  // Already loaded
        }
    }

    LoadedPlugin plugin;
    plugin.path = path.string();

    // Load the library
    plugin.handle = load_library(path);
    if (!plugin.handle) {
        spdlog::error("Failed to load plugin library: {}", path.string());
        return false;
    }

    // Get entry points
    plugin.create_func = reinterpret_cast<PluginCreateFunc>(
        get_symbol(plugin.handle, PLUGIN_CREATE_FUNC)
    );
    plugin.destroy_func = reinterpret_cast<PluginDestroyFunc>(
        get_symbol(plugin.handle, PLUGIN_DESTROY_FUNC)
    );

    if (!plugin.create_func || !plugin.destroy_func) {
        spdlog::error("Plugin missing entry points: {}", path.string());
        unload_library(plugin.handle);
        return false;
    }

    // Create plugin instance
    plugin.instance = plugin.create_func();
    if (!plugin.instance) {
        spdlog::error("Failed to create plugin instance: {}", path.string());
        unload_library(plugin.handle);
        return false;
    }

    // Validate
    if (!validate_plugin(plugin)) {
        spdlog::error("Plugin validation failed: {}", path.string());
        plugin.destroy_func(plugin.instance);
        unload_library(plugin.handle);
        return false;
    }

    plugin.name = plugin.instance->info().name;

    // Check for duplicate name
    if (name_to_index_.count(plugin.name)) {
        spdlog::error("Plugin with name '{}' already loaded", plugin.name);
        plugin.destroy_func(plugin.instance);
        unload_library(plugin.handle);
        return false;
    }

    // Add to collection
    name_to_index_[plugin.name] = plugins_.size();
    plugins_.push_back(std::move(plugin));

    spdlog::info("Loaded plugin: {} v{}",
        plugins_.back().instance->info().name,
        plugins_.back().instance->info().version);

    return true;
}

bool PluginManager::load_all_discovered() {
    auto result = discover_plugins();
    bool all_success = true;

    for (const auto& path : result.found_plugins) {
        if (!load_plugin(path)) {
            all_success = false;
        }
    }

    return all_success;
}

void PluginManager::unload_plugin(const std::string& name) {
    auto it = name_to_index_.find(name);
    if (it == name_to_index_.end()) return;

    std::size_t index = it->second;
    auto& plugin = plugins_[index];

    // Shutdown if initialized
    if (plugin.initialized && plugin.instance) {
        plugin.instance->shutdown();
        plugin.initialized = false;
    }

    // Destroy instance
    if (plugin.instance && plugin.destroy_func) {
        plugin.destroy_func(plugin.instance);
        plugin.instance = nullptr;
    }

    // Unload library
    if (plugin.handle) {
        unload_library(plugin.handle);
        plugin.handle = nullptr;
    }

    // Remove from maps
    name_to_index_.erase(it);

    // Update indices for remaining plugins
    for (auto& [n, idx] : name_to_index_) {
        if (idx > index) --idx;
    }

    plugins_.erase(plugins_.begin() + index);
}

void PluginManager::unload_all() {
    // Shutdown all first
    shutdown_all();

    // Then unload in reverse order
    while (!plugins_.empty()) {
        unload_plugin(plugins_.back().name);
    }
}

bool PluginManager::initialize_plugin(const std::string& name, PluginContext* context) {
    auto it = name_to_index_.find(name);
    if (it == name_to_index_.end()) return false;

    auto& plugin = plugins_[it->second];
    if (plugin.initialized) return true;

    if (!plugin.instance) return false;

    if (plugin.instance->initialize(context)) {
        plugin.initialized = true;
        spdlog::info("Initialized plugin: {}", name);
        return true;
    }

    spdlog::error("Failed to initialize plugin: {}", name);
    return false;
}

bool PluginManager::initialize_all(PluginContext* context) {
    bool all_success = true;

    for (auto& plugin : plugins_) {
        if (!plugin.initialized) {
            if (!initialize_plugin(plugin.name, context)) {
                all_success = false;
            }
        }
    }

    return all_success;
}

void PluginManager::shutdown_all() {
    for (auto& plugin : plugins_) {
        if (plugin.initialized && plugin.instance) {
            plugin.instance->shutdown();
            plugin.initialized = false;
        }
    }
}

bool PluginManager::is_loaded(const std::string& name) const {
    return name_to_index_.count(name) > 0;
}

bool PluginManager::is_initialized(const std::string& name) const {
    auto it = name_to_index_.find(name);
    if (it == name_to_index_.end()) return false;
    return plugins_[it->second].initialized;
}

const LoadedPlugin* PluginManager::get_plugin(const std::string& name) const {
    auto it = name_to_index_.find(name);
    if (it == name_to_index_.end()) return nullptr;
    return &plugins_[it->second];
}

std::vector<IPlugin*> PluginManager::get_plugins_by_type(PluginType type) const {
    std::vector<IPlugin*> result;
    for (const auto& plugin : plugins_) {
        if (plugin.instance && plugin.instance->info().type == type) {
            result.push_back(plugin.instance);
        }
    }
    return result;
}

std::vector<IFunctionPass*> PluginManager::get_function_passes() const {
    std::vector<IFunctionPass*> result;
    for (const auto& plugin : plugins_) {
        if (plugin.instance && plugin.instance->info().type == PluginType::FunctionPass) {
            if (auto* pass = dynamic_cast<IFunctionPass*>(plugin.instance)) {
                result.push_back(pass);
            }
        }
    }

    // Sort by priority (higher first)
    std::sort(result.begin(), result.end(),
        [](IFunctionPass* a, IFunctionPass* b) {
            return a->priority() > b->priority();
        });

    return result;
}

void PluginManager::for_each_plugin(PluginVisitor visitor) const {
    for (const auto& plugin : plugins_) {
        visitor(plugin);
    }
}

std::vector<std::string> PluginManager::get_loaded_names() const {
    std::vector<std::string> names;
    names.reserve(plugins_.size());
    for (const auto& plugin : plugins_) {
        names.push_back(plugin.name);
    }
    return names;
}

std::size_t PluginManager::initialized_count() const {
    return std::count_if(plugins_.begin(), plugins_.end(),
        [](const LoadedPlugin& p) { return p.initialized; });
}

// Platform-specific implementations
#ifdef _WIN32

void* PluginManager::load_library(const std::filesystem::path& path) {
    return LoadLibraryW(path.wstring().c_str());
}

void PluginManager::unload_library(void* handle) {
    if (handle) {
        FreeLibrary(static_cast<HMODULE>(handle));
    }
}

void* PluginManager::get_symbol(void* handle, const char* name) {
    return reinterpret_cast<void*>(
        GetProcAddress(static_cast<HMODULE>(handle), name)
    );
}

#else  // POSIX

void* PluginManager::load_library(const std::filesystem::path& path) {
    return dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
}

void PluginManager::unload_library(void* handle) {
    if (handle) {
        dlclose(handle);
    }
}

void* PluginManager::get_symbol(void* handle, const char* name) {
    return dlsym(handle, name);
}

#endif

bool PluginManager::validate_plugin(const LoadedPlugin& plugin) const {
    if (!plugin.instance) return false;

    const auto& info = plugin.instance->info();

    // Check API version
    if (info.api_version != PLUGIN_API_VERSION) {
        spdlog::warn("Plugin API version mismatch: {} has {}, expected {}",
            info.name, info.api_version, PLUGIN_API_VERSION);
        // Allow for now, but could reject
    }

    // Check required fields
    if (!info.name || !info.version) {
        return false;
    }

    return true;
}

// DefaultPluginContext implementation
void DefaultPluginContext::log_info(const char* message) {
    if (log_info_cb_) {
        log_info_cb_(message);
    } else {
        spdlog::info("[Plugin] {}", message);
    }
}

void DefaultPluginContext::log_warning(const char* message) {
    if (log_warning_cb_) {
        log_warning_cb_(message);
    } else {
        spdlog::warn("[Plugin] {}", message);
    }
}

void DefaultPluginContext::log_error(const char* message) {
    if (log_error_cb_) {
        log_error_cb_(message);
    } else {
        spdlog::error("[Plugin] {}", message);
    }
}

void DefaultPluginContext::report_progress(float progress, const char* status) {
    if (progress_cb_) {
        progress_cb_(progress, status);
    }
}

bool DefaultPluginContext::is_cancelled() const {
    return cancelled_.load(std::memory_order_relaxed);
}

const char* DefaultPluginContext::app_version() const {
    return "1.0.0";  // TODO: Get from build configuration
}

} // namespace picanha::plugin
