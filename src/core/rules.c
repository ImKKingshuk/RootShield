// RootShield Rule Engine Implementation
// ======================================
//
// Advanced rule engine for security policy evaluation and automated response.

#include "../include/rootshield.h"
#include "../include/rules.h"
#include "../include/events.h"
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/fnmatch.h>

// Rule engine configuration
#define MAX_RULES 1000
#define MAX_CONDITIONS_PER_RULE 16

// Global rule engine state
static struct rule_set *default_rule_set = NULL;
static bool rule_engine_enabled = true;
static DEFINE_SPINLOCK(rule_engine_lock);

// Rule engine statistics
static struct rule_engine_stats engine_stats = {0};

// Rule ID counter
static atomic_t rule_id_counter = ATOMIC_INIT(0);

// ============================================================================
// Core Rule Engine Functions
// ============================================================================

int init_rule_engine(void)
{
    default_rule_set = create_rule_set("default");
    if (!default_rule_set) {
        pr_err("RootShield: Failed to create default rule set\n");
        return -ENOMEM;
    }

    rule_engine_enabled = true;
    memset(&engine_stats, 0, sizeof(engine_stats));

    pr_info("RootShield: Rule engine initialized\n");
    return 0;
}

void exit_rule_engine(void)
{
    if (default_rule_set) {
        destroy_rule_set(default_rule_set);
        default_rule_set = NULL;
    }

    pr_info("RootShield: Rule engine exited (evaluations: %llu, hits: %llu)\n",
            engine_stats.total_evaluations, engine_stats.rules_hit);
}

// ============================================================================
// Rule Set Management
// ============================================================================

struct rule_set *create_rule_set(const char *name)
{
    struct rule_set *set;

    set = kzalloc(sizeof(*set), GFP_KERNEL);
    if (!set)
        return NULL;

    strncpy(set->name, name, sizeof(set->name) - 1);
    set->id = atomic_inc_return(&rule_id_counter);
    set->rules = RB_ROOT;
    spin_lock_init(&set->lock);
    atomic_set(&set->active_rules, 0);
    INIT_LIST_HEAD(&set->list);

    return set;
}

void destroy_rule_set(struct rule_set *set)
{
    struct rb_node *node;
    struct security_rule *rule;

    if (!set)
        return;

    spin_lock(&set->lock);
    // Free all rules
    while ((node = rb_first(&set->rules)) != NULL) {
        rule = rb_entry(node, struct security_rule, node);
        rb_erase(node, &set->rules);
        destroy_rule(rule);
    }
    spin_unlock(&set->lock);

    kfree(set);
}

// ============================================================================
// Rule Management
// ============================================================================

struct security_rule *create_rule(const char *name, const char *description,
                                  rule_action_t action, uint32_t priority)
{
    struct security_rule *rule;

    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule)
        return NULL;

    rule->id = atomic_inc_return(&rule_id_counter);
    strncpy(rule->name, name, sizeof(rule->name) - 1);
    if (description)
        strncpy(rule->description, description, sizeof(rule->description) - 1);
    rule->action = action;
    rule->priority = priority;
    rule->flags = 1; // Enabled by default
    INIT_LIST_HEAD(&rule->conditions);
    spin_lock_init(&rule->lock);
    rule->hit_count = 0;
    rule->last_hit = 0;

    return rule;
}

void destroy_rule(struct security_rule *rule)
{
    struct rule_condition *cond, *tmp;

    if (!rule)
        return;

    // Free all conditions
    list_for_each_entry_safe(cond, tmp, &rule->conditions, list) {
        list_del(&cond->list);
        if (cond->value.string_value)
            kfree(cond->value.string_value);
        if (cond->value2.string_value2)
            kfree(cond->value2.string_value2);
        kfree(cond);
    }

    kfree(rule);
}

static int rule_compare(struct security_rule *a, struct security_rule *b)
{
    // Higher priority first, then by ID
    if (a->priority != b->priority)
        return (a->priority > b->priority) ? -1 : 1;
    return (a->id < b->id) ? -1 : 1;
}

int add_rule_to_set(struct rule_set *set, struct security_rule *rule)
{
    struct rb_node **new, *parent = NULL;
    struct security_rule *this;
    unsigned long flags;

    if (!set || !rule)
        return -EINVAL;

    spin_lock_irqsave(&set->lock, flags);

    new = &set->rules.rb_node;
    while (*new) {
        this = rb_entry(*new, struct security_rule, node);
        parent = *new;

        int cmp = rule_compare(rule, this);
        if (cmp < 0)
            new = &((*new)->rb_left);
        else if (cmp > 0)
            new = &((*new)->rb_right);
        else {
            spin_unlock_irqrestore(&set->lock, flags);
            return -EEXIST;
        }
    }

    rb_link_node(&rule->node, parent, new);
    rb_insert_color(&rule->node, &set->rules);
    atomic_inc(&set->active_rules);

    spin_unlock_irqrestore(&set->lock, flags);

    pr_info("RootShield: Rule '%s' (id=%u, priority=%u) added to set '%s'\n",
            rule->name, rule->id, rule->priority, set->name);
    return 0;
}

int remove_rule_from_set(struct rule_set *set, uint32_t rule_id)
{
    struct rb_node *node;
    struct security_rule *rule;
    unsigned long flags;

    if (!set)
        return -EINVAL;

    spin_lock_irqsave(&set->lock, flags);

    for (node = rb_first(&set->rules); node; node = rb_next(node)) {
        rule = rb_entry(node, struct security_rule, node);
        if (rule->id == rule_id) {
            rb_erase(node, &set->rules);
            atomic_dec(&set->active_rules);
            spin_unlock_irqrestore(&set->lock, flags);
            destroy_rule(rule);
            return 0;
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);
    return -ENOENT;
}

struct security_rule *find_rule(struct rule_set *set, uint32_t rule_id)
{
    struct rb_node *node;
    struct security_rule *rule;
    unsigned long flags;

    if (!set)
        return NULL;

    spin_lock_irqsave(&set->lock, flags);

    for (node = rb_first(&set->rules); node; node = rb_next(node)) {
        rule = rb_entry(node, struct security_rule, node);
        if (rule->id == rule_id) {
            spin_unlock_irqrestore(&set->lock, flags);
            return rule;
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);
    return NULL;
}

// ============================================================================
// Condition Management
// ============================================================================

int add_string_condition(struct security_rule *rule,
                        rule_condition_type_t type,
                        rule_operator_t operator,
                        const char *value)
{
    struct rule_condition *cond;

    if (!rule || !value)
        return -EINVAL;

    cond = kzalloc(sizeof(*cond), GFP_KERNEL);
    if (!cond)
        return -ENOMEM;

    cond->type = type;
    cond->operator = operator;
    cond->value.string_value = kstrdup(value, GFP_KERNEL);
    if (!cond->value.string_value) {
        kfree(cond);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&cond->list);
    list_add_tail(&cond->list, &rule->conditions);

    return 0;
}

int add_int_condition(struct security_rule *rule,
                     rule_condition_type_t type,
                     rule_operator_t operator,
                     int value)
{
    struct rule_condition *cond;

    if (!rule)
        return -EINVAL;

    cond = kzalloc(sizeof(*cond), GFP_KERNEL);
    if (!cond)
        return -ENOMEM;

    cond->type = type;
    cond->operator = operator;
    cond->value.int_value = value;

    INIT_LIST_HEAD(&cond->list);
    list_add_tail(&cond->list, &rule->conditions);

    return 0;
}

// ============================================================================
// Condition Evaluators
// ============================================================================

static bool match_string(const char *pattern, const char *str, rule_operator_t op)
{
    if (!pattern || !str)
        return false;

    switch (op) {
    case OPERATOR_EQUALS:
        return strcmp(pattern, str) == 0;
    case OPERATOR_NOT_EQUALS:
        return strcmp(pattern, str) != 0;
    case OPERATOR_CONTAINS:
        return strstr(str, pattern) != NULL;
    case OPERATOR_NOT_CONTAINS:
        return strstr(str, pattern) == NULL;
    case OPERATOR_STARTS_WITH:
        return strncmp(str, pattern, strlen(pattern)) == 0;
    case OPERATOR_ENDS_WITH: {
        size_t slen = strlen(str);
        size_t plen = strlen(pattern);
        if (plen > slen)
            return false;
        return strcmp(str + slen - plen, pattern) == 0;
    }
    case OPERATOR_REGEX_MATCH:
        // Simple glob matching (fnmatch not available in kernel, use simple match)
        return strcmp(pattern, str) == 0; // Fallback to exact match
    default:
        return false;
    }
}

int evaluate_process_name_condition(struct rule_condition *cond,
                                   struct rule_context *ctx)
{
    if (!cond || !ctx || !ctx->task)
        return 0;

    return match_string(cond->value.string_value, ctx->task->comm, cond->operator);
}

int evaluate_file_path_condition(struct rule_condition *cond,
                                struct rule_context *ctx)
{
    if (!cond || !ctx || !ctx->event)
        return 0;

    return match_string(cond->value.string_value, ctx->event->path, cond->operator);
}

int evaluate_network_condition(struct rule_condition *cond,
                              struct rule_context *ctx)
{
    // Network condition evaluation based on port
    if (!cond || !ctx)
        return 0;

    // For port conditions
    if (cond->type == CONDITION_NETWORK_PORT) {
        // Would need network context from event
        return 0;
    }

    return 0;
}

int evaluate_syscall_condition(struct rule_condition *cond,
                              struct rule_context *ctx)
{
    if (!cond || !ctx)
        return 0;

    // Syscall conditions based on syscall number
    return 0;
}

int evaluate_uid_condition(struct rule_condition *cond, struct rule_context *ctx)
{
    if (!cond || !ctx || !ctx->event)
        return 0;

    switch (cond->operator) {
    case OPERATOR_EQUALS:
        return ctx->event->uid == (uint32_t)cond->value.int_value;
    case OPERATOR_NOT_EQUALS:
        return ctx->event->uid != (uint32_t)cond->value.int_value;
    case OPERATOR_GREATER_THAN:
        return ctx->event->uid > (uint32_t)cond->value.int_value;
    case OPERATOR_LESS_THAN:
        return ctx->event->uid < (uint32_t)cond->value.int_value;
    default:
        return 0;
    }
}

// ============================================================================
// Rule Evaluation
// ============================================================================

static int evaluate_single_condition(struct rule_condition *cond,
                                    struct rule_context *ctx)
{
    switch (cond->type) {
    case CONDITION_PROCESS_NAME:
    case CONDITION_PROCESS_PATH:
    case CONDITION_PROCESS_CMDLINE:
        return evaluate_process_name_condition(cond, ctx);

    case CONDITION_FILE_PATH:
    case CONDITION_FILE_TYPE:
        return evaluate_file_path_condition(cond, ctx);

    case CONDITION_NETWORK_PORT:
    case CONDITION_NETWORK_ADDRESS:
        return evaluate_network_condition(cond, ctx);

    case CONDITION_SYSCALL_NUMBER:
    case CONDITION_SYSCALL_ARGS:
        return evaluate_syscall_condition(cond, ctx);

    case CONDITION_USER_ID:
    case CONDITION_GROUP_ID:
        return evaluate_uid_condition(cond, ctx);

    default:
        return 0;
    }
}

int evaluate_conditions(struct security_rule *rule, struct rule_context *ctx)
{
    struct rule_condition *cond;
    int all_match = 1;

    if (!rule || !ctx)
        return 0;

    // All conditions must match (AND logic)
    list_for_each_entry(cond, &rule->conditions, list) {
        if (!evaluate_single_condition(cond, ctx)) {
            all_match = 0;
            break;
        }
    }

    return all_match;
}

rule_action_t evaluate_event(struct rule_set *set, struct rule_context *ctx)
{
    struct rb_node *node;
    struct security_rule *rule;
    rule_action_t action = RULE_TYPE_ALLOW;
    unsigned long flags;
    uint64_t start_time, end_time;

    if (!set || !ctx || !rule_engine_enabled)
        return RULE_TYPE_ALLOW;

    start_time = ktime_get_ns();
    engine_stats.total_evaluations++;

    spin_lock_irqsave(&set->lock, flags);

    // Evaluate rules in priority order (RB tree is sorted)
    for (node = rb_first(&set->rules); node; node = rb_next(node)) {
        rule = rb_entry(node, struct security_rule, node);

        // Skip disabled rules
        if (!(rule->flags & 1))
            continue;

        if (evaluate_conditions(rule, ctx)) {
            // Rule matched
            rule->hit_count++;
            rule->last_hit = ktime_get_real_ns();
            engine_stats.rules_hit++;
            action = rule->action;

            // Execute custom action if defined
            if (rule->custom_action) {
                spin_unlock_irqrestore(&set->lock, flags);
                rule->custom_action(ctx->event, rule->custom_data);
                spin_lock_irqsave(&set->lock, flags);
            }

            engine_stats.actions_taken++;
            break; // First matching rule wins
        }
    }

    spin_unlock_irqrestore(&set->lock, flags);

    end_time = ktime_get_ns();
    // Update average evaluation time (simple moving average)
    engine_stats.average_eval_time_ns = 
        (engine_stats.average_eval_time_ns * 7 + (end_time - start_time)) / 8;

    return action;
}

// ============================================================================
// Configuration Functions
// ============================================================================

int set_default_rule_set(struct rule_set *set)
{
    unsigned long flags;

    spin_lock_irqsave(&rule_engine_lock, flags);
    default_rule_set = set;
    spin_unlock_irqrestore(&rule_engine_lock, flags);

    return 0;
}

struct rule_set *get_default_rule_set(void)
{
    return default_rule_set;
}

int enable_rule_engine(bool enable)
{
    rule_engine_enabled = enable;
    pr_info("RootShield: Rule engine %s\n", enable ? "enabled" : "disabled");
    return 0;
}

bool is_rule_engine_enabled(void)
{
    return rule_engine_enabled;
}

// ============================================================================
// Statistics
// ============================================================================

void get_rule_engine_stats(struct rule_engine_stats *stats)
{
    if (stats)
        memcpy(stats, &engine_stats, sizeof(struct rule_engine_stats));
}

void reset_rule_engine_stats(void)
{
    memset(&engine_stats, 0, sizeof(engine_stats));
}

// ============================================================================
// Debugging
// ============================================================================

void dump_rule(struct security_rule *rule)
{
    struct rule_condition *cond;

    if (!rule)
        return;

    pr_info("Rule: id=%u, name='%s', action=%d, priority=%u, hits=%llu\n",
            rule->id, rule->name, rule->action, rule->priority, rule->hit_count);

    list_for_each_entry(cond, &rule->conditions, list) {
        pr_info("  Condition: type=%d, operator=%d\n", cond->type, cond->operator);
    }
}

void dump_rule_set(struct rule_set *set)
{
    struct rb_node *node;
    struct security_rule *rule;

    if (!set)
        return;

    pr_info("Rule Set: name='%s', active_rules=%d\n",
            set->name, atomic_read(&set->active_rules));

    for (node = rb_first(&set->rules); node; node = rb_next(node)) {
        rule = rb_entry(node, struct security_rule, node);
        dump_rule(rule);
    }
}

// Export symbols
EXPORT_SYMBOL(init_rule_engine);
EXPORT_SYMBOL(exit_rule_engine);
EXPORT_SYMBOL(create_rule_set);
EXPORT_SYMBOL(destroy_rule_set);
EXPORT_SYMBOL(create_rule);
EXPORT_SYMBOL(destroy_rule);
EXPORT_SYMBOL(add_rule_to_set);
EXPORT_SYMBOL(remove_rule_from_set);
EXPORT_SYMBOL(find_rule);
EXPORT_SYMBOL(evaluate_event);
EXPORT_SYMBOL(get_default_rule_set);
EXPORT_SYMBOL(enable_rule_engine);
