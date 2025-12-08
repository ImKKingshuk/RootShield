// RootShield Self-Protection Implementation
// ==========================================
//
// Mechanisms to protect the RootShield module from tampering, unloading,
// and other attacks targeting the security system itself.

#include "../include/rootshield.h"
#include "../include/self_protection.h"
#include "../include/events.h"
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/kallsyms.h>

// Self-protection state
static protection_level_t current_protection_level = PROTECTION_LEVEL_BASIC;
static bool module_locked = false;
static bool self_protection_initialized = false;
static DEFINE_SPINLOCK(protection_lock);

// Integrity hashes storage
#define MAX_INTEGRITY_CHECKS 16
static struct integrity_hash integrity_checks[MAX_INTEGRITY_CHECKS];
static int integrity_check_count = 0;

// Statistics
static struct self_protection_stats protection_stats = {0};

// Crypto handle for SHA-256
static struct crypto_shash *hash_tfm = NULL;

// ============================================================================
// Core Self-Protection Functions
// ============================================================================

int init_self_protection(protection_level_t level)
{
    if (self_protection_initialized)
        return 0;

    // Initialize crypto for integrity hashing
    hash_tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(hash_tfm)) {
        pr_warn("RootShield: SHA-256 not available, using basic protection\n");
        hash_tfm = NULL;
        // Continue without crypto - basic protection still works
    }

    current_protection_level = level;
    memset(&protection_stats, 0, sizeof(protection_stats));
    memset(integrity_checks, 0, sizeof(integrity_checks));
    integrity_check_count = 0;

    // Apply protection based on level
    if (level >= PROTECTION_LEVEL_STANDARD) {
        // Register integrity checks for critical data
        // Note: In a real implementation, we'd hash the module code section
    }

    if (level >= PROTECTION_LEVEL_HIGH) {
        enable_module_locking();
    }

    self_protection_initialized = true;

    pr_info("RootShield: Self-protection initialized (level=%d)\n", level);
    return 0;
}

void exit_self_protection(void)
{
    if (!self_protection_initialized)
        return;

    // Disable protections
    disable_module_locking();

    // Free crypto
    if (hash_tfm) {
        crypto_free_shash(hash_tfm);
        hash_tfm = NULL;
    }

    self_protection_initialized = false;

    pr_info("RootShield: Self-protection exited (incidents: %llu blocked)\n",
            protection_stats.tampering_attempts_blocked);
}

// ============================================================================
// Protection Level Management
// ============================================================================

int set_protection_level(protection_level_t level)
{
    unsigned long flags;

    spin_lock_irqsave(&protection_lock, flags);
    current_protection_level = level;
    spin_unlock_irqrestore(&protection_lock, flags);

    pr_info("RootShield: Protection level set to %d\n", level);
    return 0;
}

protection_level_t get_current_protection_level(void)
{
    return current_protection_level;
}

// ============================================================================
// Module Locking
// ============================================================================

int enable_module_locking(void)
{
    unsigned long flags;

    spin_lock_irqsave(&protection_lock, flags);
    if (!module_locked) {
        // Increment module use count to prevent unloading
        try_module_get(THIS_MODULE);
        module_locked = true;
        pr_info("RootShield: Module locked (cannot be unloaded)\n");
    }
    spin_unlock_irqrestore(&protection_lock, flags);

    return 0;
}

void disable_module_locking(void)
{
    unsigned long flags;

    spin_lock_irqsave(&protection_lock, flags);
    if (module_locked) {
        module_put(THIS_MODULE);
        module_locked = false;
        pr_info("RootShield: Module unlocked\n");
    }
    spin_unlock_irqrestore(&protection_lock, flags);
}

int is_module_locked(void)
{
    return module_locked ? 1 : 0;
}

// ============================================================================
// Integrity Monitoring
// ============================================================================

int calculate_integrity_hash(void *data, size_t size, uint8_t *hash)
{
    struct shash_desc *desc;
    int ret;

    if (!data || !hash || size == 0)
        return -EINVAL;

    if (!hash_tfm) {
        // No crypto available, use simple checksum
        uint32_t checksum = 0;
        uint8_t *bytes = (uint8_t *)data;
        size_t i;
        for (i = 0; i < size; i++) {
            checksum += bytes[i];
        }
        memset(hash, 0, 32);
        memcpy(hash, &checksum, sizeof(checksum));
        return 0;
    }

    desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(hash_tfm), GFP_KERNEL);
    if (!desc)
        return -ENOMEM;

    desc->tfm = hash_tfm;

    ret = crypto_shash_digest(desc, data, size, hash);

    kfree(desc);
    return ret;
}

int verify_integrity_hash(void *data, size_t size, const uint8_t *expected_hash)
{
    uint8_t computed_hash[32];
    int ret;

    ret = calculate_integrity_hash(data, size, computed_hash);
    if (ret < 0)
        return ret;

    if (memcmp(computed_hash, expected_hash, 32) != 0) {
        protection_stats.integrity_violations_detected++;
        return -EINVAL;
    }

    return 0;
}

int register_integrity_check(integrity_check_type_t type,
                            void *address, size_t size)
{
    unsigned long flags;
    int i;

    if (!address || size == 0)
        return -EINVAL;

    spin_lock_irqsave(&protection_lock, flags);

    if (integrity_check_count >= MAX_INTEGRITY_CHECKS) {
        spin_unlock_irqrestore(&protection_lock, flags);
        return -ENOSPC;
    }

    // Find empty slot
    for (i = 0; i < MAX_INTEGRITY_CHECKS; i++) {
        if (integrity_checks[i].address == NULL) {
            integrity_checks[i].type = type;
            integrity_checks[i].address = address;
            integrity_checks[i].size = size;
            integrity_checks[i].flags = 1;

            // Calculate initial hash
            spin_unlock_irqrestore(&protection_lock, flags);
            calculate_integrity_hash(address, size, integrity_checks[i].hash);
            integrity_checks[i].last_check = ktime_get_real_ns();
            spin_lock_irqsave(&protection_lock, flags);

            integrity_check_count++;
            spin_unlock_irqrestore(&protection_lock, flags);

            pr_info("RootShield: Registered integrity check type=%d at %p\n",
                    type, address);
            return 0;
        }
    }

    spin_unlock_irqrestore(&protection_lock, flags);
    return -ENOSPC;
}

void unregister_integrity_check(integrity_check_type_t type)
{
    unsigned long flags;
    int i;

    spin_lock_irqsave(&protection_lock, flags);
    for (i = 0; i < MAX_INTEGRITY_CHECKS; i++) {
        if (integrity_checks[i].type == type && integrity_checks[i].address) {
            memset(&integrity_checks[i], 0, sizeof(integrity_checks[i]));
            integrity_check_count--;
            break;
        }
    }
    spin_unlock_irqrestore(&protection_lock, flags);
}

int perform_integrity_check(integrity_check_type_t type)
{
    int i;
    int ret = 0;

    protection_stats.integrity_checks_performed++;

    for (i = 0; i < MAX_INTEGRITY_CHECKS; i++) {
        if (integrity_checks[i].type == type && integrity_checks[i].address) {
            ret = verify_integrity_hash(integrity_checks[i].address,
                                       integrity_checks[i].size,
                                       integrity_checks[i].hash);
            integrity_checks[i].last_check = ktime_get_real_ns();

            if (ret < 0) {
                pr_alert("RootShield: INTEGRITY VIOLATION detected (type=%d)!\n", type);
                detect_tampering_attempt("Integrity check failed");
                return ret;
            }
        }
    }

    return 0;
}

int perform_all_integrity_checks(void)
{
    int i;
    int violations = 0;

    for (i = 0; i < MAX_INTEGRITY_CHECKS; i++) {
        if (integrity_checks[i].address) {
            int ret = verify_integrity_hash(integrity_checks[i].address,
                                           integrity_checks[i].size,
                                           integrity_checks[i].hash);
            protection_stats.integrity_checks_performed++;
            integrity_checks[i].last_check = ktime_get_real_ns();

            if (ret < 0) {
                violations++;
                pr_alert("RootShield: INTEGRITY VIOLATION (type=%d at %p)!\n",
                        integrity_checks[i].type, integrity_checks[i].address);
            }
        }
    }

    if (violations > 0) {
        detect_tampering_attempt("Multiple integrity violations detected");
    }

    return violations;
}

// ============================================================================
// Anti-Tampering
// ============================================================================

int detect_tampering_attempt(const char *description)
{
    struct security_event event;

    pr_alert("RootShield: TAMPERING ATTEMPT: %s\n", description);

    protection_stats.tampering_attempts_blocked++;

    // Create security event
    memset(&event, 0, sizeof(event));
    event.type = EVENT_SECURITY_VIOLATION;
    event.severity = EVENT_SEVERITY_CRITICAL;
    event.source = "self_protection";
    event.timestamp = ktime_get_real_ns();
    event.pid = task_pid_nr(current);
    event.uid = current_uid().val;
    strncpy(event.comm, current->comm, sizeof(event.comm) - 1);
    strncpy(event.path, description, sizeof(event.path) - 1);

    // Publish event (if event system is available)
    publish_event(&event);

    return 0;
}

int block_tampering_attempt(const char *description)
{
    detect_tampering_attempt(description);

    // Take protective action
    if (current_protection_level >= PROTECTION_LEVEL_HIGH) {
        // Kill the offending process
        pr_alert("RootShield: Killing process %s (PID %d) for tampering\n",
                current->comm, task_pid_nr(current));
        send_sig(SIGKILL, current, 0);
    }

    return 0;
}

int log_security_incident(const char *description,
                         const char *details, uint32_t severity)
{
    pr_alert("RootShield: SECURITY INCIDENT (sev=%u): %s - %s\n",
            severity, description, details ? details : "");

    return 0;
}

// ============================================================================
// Rootkit Detection (integrated with anti_rootkit.c)
// ============================================================================

int scan_for_rootkits(void)
{
    int detections = 0;

    // These functions are implemented in anti_rootkit.c
    // Here we provide a unified scanning interface

    pr_info("RootShield: Starting rootkit scan...\n");

    detections += detect_hidden_modules();
    detections += detect_hidden_processes();
    detections += detect_hook_manipulation();

    pr_info("RootShield: Rootkit scan complete (%d detections)\n", detections);

    return detections;
}

int detect_hidden_modules(void)
{
    struct module *mod;
    int hidden_count = 0;

    // Cross-check module list
    mutex_lock(&module_mutex);
    list_for_each_entry(mod, THIS_MODULE->list.prev, list) {
        // Check if module is visible in /proc/modules
        // A hidden module would have manipulated the list
        if (mod->state == MODULE_STATE_LIVE) {
            // Additional checks could be added here
        }
    }
    mutex_unlock(&module_mutex);

    return hidden_count;
}

int detect_hidden_processes(void)
{
    // Would iterate task list and compare with /proc
    // Simplified implementation
    return 0;
}

int detect_hook_manipulation(void)
{
    // Would check for syscall table modifications
    // Simplified implementation
    return 0;
}

// ============================================================================
// Statistics and Monitoring  
// ============================================================================

void get_self_protection_stats(struct self_protection_stats *stats)
{
    if (stats)
        memcpy(stats, &protection_stats, sizeof(struct self_protection_stats));
}

void reset_self_protection_stats(void)
{
    memset(&protection_stats, 0, sizeof(protection_stats));
}

// ============================================================================
// Configuration
// ============================================================================

int configure_self_protection(const char *key, const char *value)
{
    if (!key || !value)
        return -EINVAL;

    if (strcmp(key, "protection_level") == 0) {
        int level = simple_strtol(value, NULL, 10);
        if (level >= 0 && level <= PROTECTION_LEVEL_MAXIMUM) {
            set_protection_level(level);
            return 0;
        }
        return -EINVAL;
    }

    if (strcmp(key, "module_locked") == 0) {
        if (strcmp(value, "1") == 0 || strcmp(value, "true") == 0) {
            enable_module_locking();
        } else {
            disable_module_locking();
        }
        return 0;
    }

    return -EINVAL;
}

// ============================================================================
// Debugging
// ============================================================================

void dump_protection_status(void)
{
    int i;

    pr_info("RootShield Self-Protection Status:\n");
    pr_info("  Protection Level: %d\n", current_protection_level);
    pr_info("  Module Locked: %s\n", module_locked ? "yes" : "no");
    pr_info("  Integrity Checks: %d registered\n", integrity_check_count);
    pr_info("  Stats: checks=%llu, violations=%llu, blocked=%llu\n",
            protection_stats.integrity_checks_performed,
            protection_stats.integrity_violations_detected,
            protection_stats.tampering_attempts_blocked);

    for (i = 0; i < MAX_INTEGRITY_CHECKS; i++) {
        if (integrity_checks[i].address) {
            pr_info("    Check[%d]: type=%d, addr=%p, size=%zu\n",
                    i, integrity_checks[i].type,
                    integrity_checks[i].address,
                    integrity_checks[i].size);
        }
    }
}

// Export symbols
EXPORT_SYMBOL(init_self_protection);
EXPORT_SYMBOL(exit_self_protection);
EXPORT_SYMBOL(set_protection_level);
EXPORT_SYMBOL(get_current_protection_level);
EXPORT_SYMBOL(enable_module_locking);
EXPORT_SYMBOL(disable_module_locking);
EXPORT_SYMBOL(is_module_locked);
EXPORT_SYMBOL(register_integrity_check);
EXPORT_SYMBOL(perform_all_integrity_checks);
EXPORT_SYMBOL(detect_tampering_attempt);
EXPORT_SYMBOL(scan_for_rootkits);
