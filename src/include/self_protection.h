// RootShield Self-Protection System
// ==================================
//
// Mechanisms to protect the RootShield module from tampering, unloading,
// and other attacks targeting the security system itself.

#ifndef ROOTSHIELD_SELF_PROTECTION_H
#define ROOTSHIELD_SELF_PROTECTION_H

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/integrity.h>
#include <linux/crypto.h>

// Self-protection capabilities
#define SELF_PROTECT_HOOK_INTEGRITY     (1 << 0)  // Hook integrity checking
#define SELF_PROTECT_MODULE_LOCKING     (1 << 1)  // Prevent forced unloading
#define SELF_PROTECT_MEMORY_PROTECTION  (1 << 2)  // Protect own memory
#define SELF_PROTECT_SYSCALL_PROTECTION (1 << 3)  // Protect critical syscalls
#define SELF_PROTECT_KPROBE_PROTECTION  (1 << 4)  // Protect kprobe hooks
#define SELF_PROTECT_MODULE_HIDING      (1 << 5)  // Hide from lsmod/module lists
#define SELF_PROTECT_ROOTKIT_DETECTION  (1 << 6)  // Detect attempts to compromise
#define SELF_PROTECT_INTEGRITY_MONITOR  (1 << 7)  // Continuous integrity monitoring

// Protection levels
typedef enum {
    PROTECTION_LEVEL_BASIC = 0,      // Basic anti-unloading protection
    PROTECTION_LEVEL_STANDARD,       // Standard protection + integrity checks
    PROTECTION_LEVEL_HIGH,           // High protection + memory protection
    PROTECTION_LEVEL_MAXIMUM         // Maximum protection + rootkit detection
} protection_level_t;

// Integrity check types
typedef enum {
    INTEGRITY_CHECK_MODULE_CODE = 0,
    INTEGRITY_CHECK_HOOKS,
    INTEGRITY_CHECK_MEMORY,
    INTEGRITY_CHECK_SYSCALL_TABLE,
    INTEGRITY_CHECK_IDT,
    INTEGRITY_CHECK_KPROBE_LIST,
    INTEGRITY_CHECK_MODULE_LIST
} integrity_check_type_t;

// Integrity hash structure
struct integrity_hash {
    uint8_t hash[32];           // SHA-256 hash
    size_t size;               // Size of protected data
    void *address;             // Memory address
    integrity_check_type_t type;
    uint64_t last_check;       // Timestamp of last integrity check
    uint32_t flags;
};

// Self-protection statistics
struct self_protection_stats {
    uint64_t integrity_checks_performed;
    uint64_t integrity_violations_detected;
    uint64_t tampering_attempts_blocked;
    uint64_t memory_protection_events;
    uint64_t hook_protection_events;
    uint64_t uptime_protected_seconds;
};

// Core self-protection functions
extern int init_self_protection(protection_level_t level);
extern void exit_self_protection(void);

// Protection level management
extern int set_protection_level(protection_level_t level);
extern protection_level_t get_current_protection_level(void);

// Integrity monitoring functions
extern int register_integrity_check(integrity_check_type_t type,
                                   void *address, size_t size);
extern void unregister_integrity_check(integrity_check_type_t type);
extern int perform_integrity_check(integrity_check_type_t type);
extern int perform_all_integrity_checks(void);

// Module protection functions
extern int enable_module_locking(void);
extern void disable_module_locking(void);
extern int is_module_locked(void);

// Memory protection functions
extern int protect_module_memory(void);
extern void unprotect_module_memory(void);
extern int verify_memory_integrity(void);

// Hook protection functions
extern int protect_kprobes(void);
extern void unprotect_kprobes(void);
extern int verify_hook_integrity(void);

// Anti-tampering functions
extern int detect_tampering_attempt(const char *description);
extern int block_tampering_attempt(const char *description);
extern int log_security_incident(const char *description,
                                const char *details, uint32_t severity);

// Rootkit detection functions
extern int scan_for_rootkits(void);
extern int detect_hidden_modules(void);
extern int detect_hidden_processes(void);
extern int detect_hook_manipulation(void);

// Cryptographic functions for integrity
extern int calculate_integrity_hash(void *data, size_t size, uint8_t *hash);
extern int verify_integrity_hash(void *data, size_t size, const uint8_t *expected_hash);

// Self-healing functions
extern int attempt_self_healing(void);
extern int restore_integrity(void);

// Statistics and monitoring
extern void get_self_protection_stats(struct self_protection_stats *stats);
extern void reset_self_protection_stats(void);

// Configuration
extern int configure_self_protection(const char *key, const char *value);
extern int get_self_protection_config(const char *key, char *value, size_t size);

// Emergency functions
extern void enter_emergency_mode(void);
extern void exit_emergency_mode(void);
extern bool is_in_emergency_mode(void);

// Integration with other components
extern int register_self_protection_with_events(void);
extern int register_self_protection_with_plugins(void);

// Advanced protection features
extern int enable_hardware_assisted_protection(void);
extern int enable_secure_boot_verification(void);
extern int enable_tpm_integration(void);

// Protection against specific attacks
extern int protect_against_module_hiding(void);
extern int protect_against_hook_hiding(void);
extern int protect_against_memory_hiding(void);
extern int protect_against_syscall_hiding(void);

// Debugging and testing
extern void enable_self_protection_debug(bool enable);
extern int test_self_protection_mechanisms(void);
extern void dump_protection_status(void);

#endif /* ROOTSHIELD_SELF_PROTECTION_H */
