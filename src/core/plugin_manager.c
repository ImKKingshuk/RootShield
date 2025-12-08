// RootShield Plugin Manager Implementation
// =========================================
//
// Plugin lifecycle management, registration, and inter-plugin communication.

#include "../include/rootshield.h"
#include "../include/plugin.h"
#include "../include/events.h"
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/kobject.h>
#include <linux/string.h>

// Plugin manager configuration
#define MAX_PLUGINS 32

// Global plugin registry
static LIST_HEAD(plugin_list);
static DEFINE_SPINLOCK(plugin_list_lock);
static int plugin_count = 0;

// Plugin manager state
static struct kobject *plugins_kobj = NULL;
static bool plugin_manager_initialized = false;

// ============================================================================
// Plugin Registration
// ============================================================================

int register_plugin(struct rootshield_plugin *plugin)
{
    unsigned long flags;

    if (!plugin || !plugin->metadata || !plugin->ops)
        return -EINVAL;

    if (!plugin->metadata->name) {
        pr_err("RootShield: Cannot register plugin without name\n");
        return -EINVAL;
    }

    if (plugin_count >= MAX_PLUGINS) {
        pr_err("RootShield: Maximum plugins reached\n");
        return -ENOSPC;
    }

    // Check for duplicate
    spin_lock_irqsave(&plugin_list_lock, flags);
    {
        struct rootshield_plugin *p;
        list_for_each_entry(p, &plugin_list, list) {
            if (strcmp(p->metadata->name, plugin->metadata->name) == 0) {
                spin_unlock_irqrestore(&plugin_list_lock, flags);
                pr_warn("RootShield: Plugin '%s' already registered\n",
                        plugin->metadata->name);
                return -EEXIST;
            }
        }
    }

    // Initialize plugin
    spin_lock_init(&plugin->lock);
    atomic_set(&plugin->ref_count, 0);
    INIT_LIST_HEAD(&plugin->list);
    plugin->state = PLUGIN_STATE_LOADED;

    // Add to registry
    list_add_tail(&plugin->list, &plugin_list);
    plugin_count++;
    spin_unlock_irqrestore(&plugin_list_lock, flags);

    pr_info("RootShield: Plugin '%s' v%s registered (type=%d, caps=0x%x)\n",
            plugin->metadata->name,
            plugin->metadata->version ? plugin->metadata->version : "unknown",
            plugin->metadata->type,
            plugin->metadata->capabilities);

    return 0;
}

void unregister_plugin(struct rootshield_plugin *plugin)
{
    unsigned long flags;

    if (!plugin)
        return;

    // Stop plugin if running
    if (plugin->state == PLUGIN_STATE_ACTIVE && plugin->ops->stop) {
        plugin->ops->stop(plugin->private_data);
    }

    // Exit plugin if initialized
    if (plugin->state >= PLUGIN_STATE_INITIALIZED && plugin->ops->exit) {
        plugin->ops->exit(plugin->private_data);
    }

    // Remove from registry
    spin_lock_irqsave(&plugin_list_lock, flags);
    list_del(&plugin->list);
    plugin_count--;
    spin_unlock_irqrestore(&plugin_list_lock, flags);

    plugin->state = PLUGIN_STATE_UNLOADED;

    pr_info("RootShield: Plugin '%s' unregistered\n", plugin->metadata->name);
}

// ============================================================================
// Plugin Lookup
// ============================================================================

struct rootshield_plugin *find_plugin(const char *name)
{
    struct rootshield_plugin *plugin;
    unsigned long flags;

    if (!name)
        return NULL;

    spin_lock_irqsave(&plugin_list_lock, flags);
    list_for_each_entry(plugin, &plugin_list, list) {
        if (strcmp(plugin->metadata->name, name) == 0) {
            spin_unlock_irqrestore(&plugin_list_lock, flags);
            return plugin;
        }
    }
    spin_unlock_irqrestore(&plugin_list_lock, flags);

    return NULL;
}

// ============================================================================
// Plugin Lifecycle Management
// ============================================================================

int load_plugin(const char *name)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin) {
        pr_err("RootShield: Plugin '%s' not found\n", name);
        return -ENOENT;
    }

    if (plugin->state != PLUGIN_STATE_LOADED) {
        pr_warn("RootShield: Plugin '%s' not in loaded state\n", name);
        return -EINVAL;
    }

    // Initialize plugin
    if (plugin->ops->init) {
        int ret = plugin->ops->init(plugin->private_data);
        if (ret < 0) {
            pr_err("RootShield: Plugin '%s' init failed: %d\n", name, ret);
            plugin->state = PLUGIN_STATE_ERROR;
            return ret;
        }
    }

    plugin->state = PLUGIN_STATE_INITIALIZED;
    pr_info("RootShield: Plugin '%s' initialized\n", name);

    return 0;
}

int unload_plugin(const char *name)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin) {
        return -ENOENT;
    }

    // Stop if active
    if (plugin->state == PLUGIN_STATE_ACTIVE) {
        disable_plugin(name);
    }

    // Exit plugin
    if (plugin->ops->exit) {
        plugin->ops->exit(plugin->private_data);
    }

    plugin->state = PLUGIN_STATE_LOADED;
    pr_info("RootShield: Plugin '%s' unloaded\n", name);

    return 0;
}

int enable_plugin(const char *name)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin) {
        return -ENOENT;
    }

    if (plugin->state == PLUGIN_STATE_ACTIVE) {
        return 0; // Already active
    }

    if (plugin->state != PLUGIN_STATE_INITIALIZED) {
        // Try to initialize first
        int ret = load_plugin(name);
        if (ret < 0)
            return ret;
    }

    // Start plugin
    if (plugin->ops->start) {
        int ret = plugin->ops->start(plugin->private_data);
        if (ret < 0) {
            pr_err("RootShield: Plugin '%s' start failed: %d\n", name, ret);
            plugin->state = PLUGIN_STATE_ERROR;
            return ret;
        }
    }

    plugin->state = PLUGIN_STATE_ACTIVE;
    pr_info("RootShield: Plugin '%s' started\n", name);

    return 0;
}

int disable_plugin(const char *name)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin) {
        return -ENOENT;
    }

    if (plugin->state != PLUGIN_STATE_ACTIVE) {
        return 0; // Already stopped
    }

    // Stop plugin
    if (plugin->ops->stop) {
        plugin->ops->stop(plugin->private_data);
    }

    plugin->state = PLUGIN_STATE_DISABLED;
    pr_info("RootShield: Plugin '%s' stopped\n", name);

    return 0;
}

// ============================================================================
// Plugin Configuration
// ============================================================================

int configure_plugin(const char *name, const char *key, const char *value)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin)
        return -ENOENT;

    if (!plugin->ops->configure)
        return -ENOSYS;

    return plugin->ops->configure(plugin->private_data, key, value);
}

int get_plugin_config(const char *name, const char *key, char *value, size_t size)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin)
        return -ENOENT;

    if (!plugin->ops->get_config)
        return -ENOSYS;

    return plugin->ops->get_config(plugin->private_data, key, value, size);
}

// ============================================================================
// Plugin Event Broadcasting
// ============================================================================

int send_event_to_plugin(struct rootshield_plugin *plugin, struct security_event *event)
{
    if (!plugin || !event)
        return -EINVAL;

    if (plugin->state != PLUGIN_STATE_ACTIVE)
        return -EINVAL;

    if (!plugin->ops->handle_event)
        return -ENOSYS;

    return plugin->ops->handle_event(plugin->private_data, event);
}

int broadcast_event(struct security_event *event, uint32_t target_capabilities)
{
    struct rootshield_plugin *plugin;
    unsigned long flags;
    int count = 0;

    if (!event)
        return -EINVAL;

    spin_lock_irqsave(&plugin_list_lock, flags);
    list_for_each_entry(plugin, &plugin_list, list) {
        // Check if plugin is active and has matching capabilities
        if (plugin->state != PLUGIN_STATE_ACTIVE)
            continue;

        if (target_capabilities != 0 &&
            !(plugin->metadata->capabilities & target_capabilities))
            continue;

        if (plugin->ops->handle_event) {
            spin_unlock_irqrestore(&plugin_list_lock, flags);
            plugin->ops->handle_event(plugin->private_data, event);
            spin_lock_irqsave(&plugin_list_lock, flags);
            count++;
        }
    }
    spin_unlock_irqrestore(&plugin_list_lock, flags);

    return count;
}

// ============================================================================
// Plugin Dependencies
// ============================================================================

int check_dependencies(struct rootshield_plugin *plugin)
{
    int i;

    if (!plugin || !plugin->metadata)
        return 0;

    for (i = 0; i < 16 && plugin->metadata->dependencies[i]; i++) {
        struct rootshield_plugin *dep = find_plugin(plugin->metadata->dependencies[i]);
        if (!dep) {
            pr_warn("RootShield: Plugin '%s' missing dependency '%s'\n",
                    plugin->metadata->name, plugin->metadata->dependencies[i]);
            return -ENOENT;
        }
        if (dep->state < PLUGIN_STATE_INITIALIZED) {
            pr_warn("RootShield: Plugin '%s' dependency '%s' not initialized\n",
                    plugin->metadata->name, plugin->metadata->dependencies[i]);
            return -EAGAIN;
        }
    }

    return 0;
}

int resolve_dependencies(struct rootshield_plugin *plugin)
{
    int i;

    if (!plugin || !plugin->metadata)
        return 0;

    for (i = 0; i < 16 && plugin->metadata->dependencies[i]; i++) {
        struct rootshield_plugin *dep = find_plugin(plugin->metadata->dependencies[i]);
        if (!dep) {
            return -ENOENT;
        }
        if (dep->state < PLUGIN_STATE_INITIALIZED) {
            int ret = load_plugin(plugin->metadata->dependencies[i]);
            if (ret < 0)
                return ret;
        }
    }

    return 0;
}

// ============================================================================
// Plugin Statistics
// ============================================================================

int get_plugin_stats(const char *name, struct plugin_stats *stats)
{
    struct rootshield_plugin *plugin;

    if (!stats)
        return -EINVAL;

    plugin = find_plugin(name);
    if (!plugin)
        return -ENOENT;

    if (!plugin->ops->get_stats)
        return -ENOSYS;

    return plugin->ops->get_stats(plugin->private_data, stats);
}

int plugin_health_check(const char *name)
{
    struct rootshield_plugin *plugin;

    plugin = find_plugin(name);
    if (!plugin)
        return -ENOENT;

    if (!plugin->ops->health_check)
        return 0; // No health check = healthy

    return plugin->ops->health_check(plugin->private_data);
}

// ============================================================================
// Plugin Manager Initialization
// ============================================================================

int init_plugin_manager(void)
{
    if (plugin_manager_initialized)
        return 0;

    INIT_LIST_HEAD(&plugin_list);
    spin_lock_init(&plugin_list_lock);
    plugin_count = 0;

    plugin_manager_initialized = true;

    pr_info("RootShield: Plugin manager initialized\n");
    return 0;
}

void exit_plugin_manager(void)
{
    struct rootshield_plugin *plugin, *tmp;
    unsigned long flags;

    if (!plugin_manager_initialized)
        return;

    // Unregister all plugins
    spin_lock_irqsave(&plugin_list_lock, flags);
    list_for_each_entry_safe(plugin, tmp, &plugin_list, list) {
        spin_unlock_irqrestore(&plugin_list_lock, flags);
        unregister_plugin(plugin);
        spin_lock_irqsave(&plugin_list_lock, flags);
    }
    spin_unlock_irqrestore(&plugin_list_lock, flags);

    plugin_manager_initialized = false;

    pr_info("RootShield: Plugin manager exited\n");
}

// ============================================================================
// Plugin Enumeration
// ============================================================================

int get_plugin_count(void)
{
    return plugin_count;
}

void enumerate_plugins(void (*callback)(struct rootshield_plugin *, void *), void *data)
{
    struct rootshield_plugin *plugin;
    unsigned long flags;

    if (!callback)
        return;

    spin_lock_irqsave(&plugin_list_lock, flags);
    list_for_each_entry(plugin, &plugin_list, list) {
        spin_unlock_irqrestore(&plugin_list_lock, flags);
        callback(plugin, data);
        spin_lock_irqsave(&plugin_list_lock, flags);
    }
    spin_unlock_irqrestore(&plugin_list_lock, flags);
}

// ============================================================================
// Debugging
// ============================================================================

void dump_plugins(void)
{
    struct rootshield_plugin *plugin;
    unsigned long flags;

    pr_info("RootShield: Plugin Registry (%d plugins)\n", plugin_count);

    spin_lock_irqsave(&plugin_list_lock, flags);
    list_for_each_entry(plugin, &plugin_list, list) {
        pr_info("  - %s v%s (state=%d, caps=0x%x, refs=%d)\n",
                plugin->metadata->name,
                plugin->metadata->version ? plugin->metadata->version : "?",
                plugin->state,
                plugin->metadata->capabilities,
                atomic_read(&plugin->ref_count));
    }
    spin_unlock_irqrestore(&plugin_list_lock, flags);
}

// Export symbols
EXPORT_SYMBOL(register_plugin);
EXPORT_SYMBOL(unregister_plugin);
EXPORT_SYMBOL(find_plugin);
EXPORT_SYMBOL(load_plugin);
EXPORT_SYMBOL(unload_plugin);
EXPORT_SYMBOL(enable_plugin);
EXPORT_SYMBOL(disable_plugin);
EXPORT_SYMBOL(send_event_to_plugin);
EXPORT_SYMBOL(broadcast_event);
EXPORT_SYMBOL(check_dependencies);
EXPORT_SYMBOL(init_plugin_manager);
EXPORT_SYMBOL(exit_plugin_manager);
