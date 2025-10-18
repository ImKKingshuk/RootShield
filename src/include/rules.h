// RootShield Rule Engine
// =======================
//
// Advanced rule engine for security policy evaluation and automated response.

#ifndef ROOTSHIELD_RULES_H
#define ROOTSHIELD_RULES_H

#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

// Rule types
typedef enum {
    RULE_TYPE_ALLOW = 0,
    RULE_TYPE_DENY,
    RULE_TYPE_LOG,
    RULE_TYPE_ALERT,
    RULE_TYPE_QUARANTINE,
    RULE_TYPE_KILL,
    RULE_TYPE_CUSTOM
} rule_action_t;

// Rule conditions
typedef enum {
    CONDITION_PROCESS_NAME = 0,
    CONDITION_PROCESS_PATH,
    CONDITION_PROCESS_CMDLINE,
    CONDITION_FILE_PATH,
    CONDITION_FILE_TYPE,
    CONDITION_NETWORK_PORT,
    CONDITION_NETWORK_ADDRESS,
    CONDITION_SYSCALL_NUMBER,
    CONDITION_SYSCALL_ARGS,
    CONDITION_MEMORY_REGION,
    CONDITION_MODULE_NAME,
    CONDITION_USER_ID,
    CONDITION_GROUP_ID,
    CONDITION_TIME_RANGE,
    CONDITION_FREQUENCY,
    CONDITION_ANOMALY_SCORE,
    CONDITION_CUSTOM = 1000
} rule_condition_type_t;

// Rule operators
typedef enum {
    OPERATOR_EQUALS = 0,
    OPERATOR_NOT_EQUALS,
    OPERATOR_CONTAINS,
    OPERATOR_NOT_CONTAINS,
    OPERATOR_STARTS_WITH,
    OPERATOR_ENDS_WITH,
    OPERATOR_REGEX_MATCH,
    OPERATOR_GREATER_THAN,
    OPERATOR_LESS_THAN,
    OPERATOR_BETWEEN,
    OPERATOR_IN_LIST,
    OPERATOR_NOT_IN_LIST
} rule_operator_t;

// Rule condition structure
struct rule_condition {
    rule_condition_type_t type;
    rule_operator_t operator;
    union {
        char *string_value;
        int int_value;
        unsigned int uint_value;
        long long_value;
        unsigned long ulong_value;
        void *ptr_value;
    } value;
    union {
        char *string_value2;
        int int_value2;
        unsigned int uint_value2;
        long long_value2;
        unsigned long ulong_value2;
        void *ptr_value2;
    } value2;  // For range operations
    struct list_head list;
};

// Rule structure
struct security_rule {
    uint32_t id;
    char name[64];
    char description[256];
    rule_action_t action;
    uint32_t priority;              // Higher priority rules are evaluated first
    uint32_t flags;                 // Rule flags (enabled, temporary, etc.)
    struct list_head conditions;    // List of conditions
    void (*custom_action)(struct security_event *, void *);  // Custom action callback
    void *custom_data;              // Data for custom action
    uint64_t hit_count;             // Number of times rule has been triggered
    uint64_t last_hit;              // Timestamp of last hit
    struct rb_node node;            // Red-black tree node for fast lookup
    spinlock_t lock;
};

// Rule set structure
struct rule_set {
    char name[64];
    uint32_t id;
    uint32_t flags;
    struct rb_root rules;           // Red-black tree of rules
    spinlock_t lock;
    atomic_t active_rules;
    struct list_head list;
};

// Rule evaluation context
struct rule_context {
    struct security_event *event;
    struct task_struct *task;
    struct cred *cred;
    void *private_data;
    uint32_t flags;
};

// Rule engine statistics
struct rule_engine_stats {
    uint64_t total_evaluations;
    uint64_t rules_hit;
    uint64_t actions_taken;
    uint64_t evaluation_errors;
    uint64_t average_eval_time_ns;
};

// Core rule engine functions
extern int init_rule_engine(void);
extern void exit_rule_engine(void);

// Rule management functions
extern struct security_rule *create_rule(const char *name, const char *description,
                                        rule_action_t action, uint32_t priority);
extern void destroy_rule(struct security_rule *rule);
extern int add_rule_to_set(struct rule_set *set, struct security_rule *rule);
extern int remove_rule_from_set(struct rule_set *set, uint32_t rule_id);
extern struct security_rule *find_rule(struct rule_set *set, uint32_t rule_id);

// Rule condition management
extern int add_condition_to_rule(struct security_rule *rule,
                                rule_condition_type_t type,
                                rule_operator_t operator,
                                ...);  // Variable arguments for values
extern int remove_condition_from_rule(struct security_rule *rule, uint32_t condition_index);

// Rule set management
extern struct rule_set *create_rule_set(const char *name);
extern void destroy_rule_set(struct rule_set *set);
extern int load_rule_set(const char *filename);
extern int save_rule_set(struct rule_set *set, const char *filename);

// Rule evaluation functions
extern rule_action_t evaluate_event(struct rule_set *set,
                                   struct rule_context *context);
extern int evaluate_conditions(struct security_rule *rule,
                              struct rule_context *context);

// Built-in condition evaluators
extern int evaluate_process_name_condition(struct rule_condition *cond,
                                          struct rule_context *ctx);
extern int evaluate_file_path_condition(struct rule_condition *cond,
                                       struct rule_context *ctx);
extern int evaluate_network_condition(struct rule_condition *cond,
                                     struct rule_context *ctx);
extern int evaluate_syscall_condition(struct rule_condition *cond,
                                     struct rule_context *ctx);

// Custom condition registration
extern int register_condition_evaluator(rule_condition_type_t type,
                                       int (*evaluator)(struct rule_condition *,
                                                       struct rule_context *));
extern void unregister_condition_evaluator(rule_condition_type_t type);

// Rule engine configuration
extern int set_default_rule_set(struct rule_set *set);
extern struct rule_set *get_default_rule_set(void);
extern int enable_rule_engine(bool enable);
extern bool is_rule_engine_enabled(void);

// Statistics and monitoring
extern void get_rule_engine_stats(struct rule_engine_stats *stats);
extern void reset_rule_engine_stats(void);

// Rule validation
extern int validate_rule(struct security_rule *rule);
extern int validate_rule_set(struct rule_set *set);

// Rule compilation (for performance)
extern int compile_rule(struct security_rule *rule);
extern int compile_rule_set(struct rule_set *set);

// Rule debugging
extern void dump_rule(struct security_rule *rule);
extern void dump_rule_set(struct rule_set *set);
extern void enable_rule_debugging(bool enable);

// Integration with other components
extern int register_rule_engine_with_events(void);
extern int register_rule_engine_with_plugins(void);

#endif /* ROOTSHIELD_RULES_H */
