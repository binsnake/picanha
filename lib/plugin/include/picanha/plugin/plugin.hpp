#pragma once

#include <picanha/core/types.hpp>
#include <string>
#include <cstdint>
#include <memory>

namespace picanha::plugin {

// Plugin API version for compatibility checking
constexpr std::uint32_t PLUGIN_API_VERSION = 1;

// Plugin type
enum class PluginType : std::uint8_t {
    FunctionPass,       // Analyzes/transforms functions
    Loader,             // Binary format loader
    Exporter,           // Export to other formats
    UI,                 // UI extension
    Generic,            // Generic plugin
};

// Plugin capabilities flags
enum class PluginCapabilities : std::uint32_t {
    None                = 0,
    ThreadSafe          = 1 << 0,   // Can be called from multiple threads
    Configurable        = 1 << 1,   // Has configuration options
    HasUI               = 1 << 2,   // Provides UI elements
    ModifiesCode        = 1 << 3,   // Can modify disassembly
    ModifiesData        = 1 << 4,   // Can modify data analysis
    RequiresProject     = 1 << 5,   // Needs an open project
};

inline PluginCapabilities operator|(PluginCapabilities a, PluginCapabilities b) {
    return static_cast<PluginCapabilities>(
        static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b)
    );
}

inline PluginCapabilities operator&(PluginCapabilities a, PluginCapabilities b) {
    return static_cast<PluginCapabilities>(
        static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b)
    );
}

inline bool has_capability(PluginCapabilities caps, PluginCapabilities cap) {
    return (static_cast<std::uint32_t>(caps) & static_cast<std::uint32_t>(cap)) != 0;
}

// Plugin metadata
struct PluginInfo {
    const char* name;
    const char* version;
    const char* author;
    const char* description;
    PluginType type;
    PluginCapabilities capabilities;
    std::uint32_t api_version;
};

// Forward declarations
class PluginContext;

// Base plugin interface
class IPlugin {
public:
    virtual ~IPlugin() = default;

    // Get plugin information
    [[nodiscard]] virtual const PluginInfo& info() const = 0;

    // Initialize plugin with context
    virtual bool initialize(PluginContext* context) = 0;

    // Shutdown plugin
    virtual void shutdown() = 0;

    // Check if plugin is initialized
    [[nodiscard]] virtual bool is_initialized() const = 0;
};

// Plugin context - provides access to application services
class PluginContext {
public:
    virtual ~PluginContext() = default;

    // Logging
    virtual void log_info(const char* message) = 0;
    virtual void log_warning(const char* message) = 0;
    virtual void log_error(const char* message) = 0;

    // Progress reporting
    virtual void report_progress(float progress, const char* status) = 0;

    // Check for cancellation
    [[nodiscard]] virtual bool is_cancelled() const = 0;

    // Get application version
    [[nodiscard]] virtual const char* app_version() const = 0;
};

// Plugin factory function type
using PluginCreateFunc = IPlugin* (*)();
using PluginDestroyFunc = void (*)(IPlugin*);

// Plugin entry point names (for dynamic loading)
constexpr const char* PLUGIN_CREATE_FUNC = "picanha_plugin_create";
constexpr const char* PLUGIN_DESTROY_FUNC = "picanha_plugin_destroy";

// Macro to define plugin entry points
#define PICANHA_PLUGIN_ENTRY(PluginClass) \
    extern "C" { \
        __declspec(dllexport) ::picanha::plugin::IPlugin* picanha_plugin_create() { \
            return new PluginClass(); \
        } \
        __declspec(dllexport) void picanha_plugin_destroy(::picanha::plugin::IPlugin* plugin) { \
            delete plugin; \
        } \
    }

} // namespace picanha::plugin
