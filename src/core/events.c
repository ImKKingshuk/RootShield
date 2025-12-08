// RootShield Event System Implementation
// ========================================
//
// High-performance publish-subscribe event system for inter-component
// communication and centralized event processing.

#include "../include/rootshield.h"
#include "../include/events.h"
#include <linux/kfifo.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/list.h>

// Event queue configuration
#define EVENT_QUEUE_SIZE 256
#define MAX_SUBSCRIBERS 32

// Global event dispatcher
static struct event_dispatcher *g_dispatcher = NULL;

// Event ID counter
static atomic64_t event_id_counter = ATOMIC64_INIT(0);

// Subscriber list
static LIST_HEAD(subscriber_list);
static DEFINE_SPINLOCK(subscriber_lock);
static int subscriber_count = 0;

// Event queue (circular buffer)
static struct security_event event_queue[EVENT_QUEUE_SIZE];
static DEFINE_SPINLOCK(queue_lock);
static int queue_head = 0;
static int queue_tail = 0;
static atomic_t queue_count = ATOMIC_INIT(0);

// Statistics
static uint64_t total_events = 0;
static uint64_t processed_events = 0;
static uint64_t dropped_events = 0;

// Forward declarations
static void event_dispatch_worker(struct work_struct *work);

// ============================================================================
// Core Event System Functions
// ============================================================================

int init_event_system(void)
{
    g_dispatcher = kzalloc(sizeof(struct event_dispatcher), GFP_KERNEL);
    if (!g_dispatcher) {
        pr_err("RootShield: Failed to allocate event dispatcher\n");
        return -ENOMEM;
    }

    // Initialize subscriber list
    INIT_LIST_HEAD(&g_dispatcher->subscribers);
    spin_lock_init(&g_dispatcher->subscribers_lock);

    // Initialize workqueue for async processing
    g_dispatcher->workqueue = create_singlethread_workqueue("rootshield_events");
    if (!g_dispatcher->workqueue) {
        pr_err("RootShield: Failed to create event workqueue\n");
        kfree(g_dispatcher);
        g_dispatcher = NULL;
        return -ENOMEM;
    }

    INIT_DELAYED_WORK(&g_dispatcher->dispatch_work, event_dispatch_worker);
    atomic_set(&g_dispatcher->running, 1);

    // Reset statistics
    total_events = 0;
    processed_events = 0;
    dropped_events = 0;

    pr_info("RootShield: Event system initialized\n");
    return 0;
}

void exit_event_system(void)
{
    struct event_subscriber *sub, *tmp;

    if (!g_dispatcher)
        return;

    // Stop dispatcher
    atomic_set(&g_dispatcher->running, 0);

    // Cancel pending work
    cancel_delayed_work_sync(&g_dispatcher->dispatch_work);

    // Destroy workqueue
    if (g_dispatcher->workqueue) {
        destroy_workqueue(g_dispatcher->workqueue);
    }

    // Clean up subscribers
    spin_lock(&subscriber_lock);
    list_for_each_entry_safe(sub, tmp, &subscriber_list, list) {
        list_del(&sub->list);
        kfree(sub);
    }
    subscriber_count = 0;
    spin_unlock(&subscriber_lock);

    kfree(g_dispatcher);
    g_dispatcher = NULL;

    pr_info("RootShield: Event system exited (total: %llu, processed: %llu, dropped: %llu)\n",
            total_events, processed_events, dropped_events);
}

// ============================================================================
// Event Publishing Functions
// ============================================================================

int publish_event(struct security_event *event)
{
    unsigned long flags;
    int next_tail;

    if (!g_dispatcher || !event)
        return -EINVAL;

    // Assign unique event ID and timestamp
    event->id = atomic64_inc_return(&event_id_counter);
    if (event->timestamp == 0) {
        event->timestamp = ktime_get_real_ns();
    }

    spin_lock_irqsave(&queue_lock, flags);

    // Check if queue is full
    next_tail = (queue_tail + 1) % EVENT_QUEUE_SIZE;
    if (next_tail == queue_head) {
        // Queue full, drop oldest event
        queue_head = (queue_head + 1) % EVENT_QUEUE_SIZE;
        dropped_events++;
    }

    // Copy event to queue
    memcpy(&event_queue[queue_tail], event, sizeof(struct security_event));
    queue_tail = next_tail;
    atomic_inc(&queue_count);
    total_events++;

    spin_unlock_irqrestore(&queue_lock, flags);

    // Schedule immediate dispatch
    if (atomic_read(&g_dispatcher->running)) {
        queue_delayed_work(g_dispatcher->workqueue, &g_dispatcher->dispatch_work, 0);
    }

    return 0;
}

int publish_event_async(struct security_event *event)
{
    // Same as publish_event but with delayed dispatch
    unsigned long flags;
    int next_tail;

    if (!g_dispatcher || !event)
        return -EINVAL;

    event->id = atomic64_inc_return(&event_id_counter);
    if (event->timestamp == 0) {
        event->timestamp = ktime_get_real_ns();
    }

    spin_lock_irqsave(&queue_lock, flags);

    next_tail = (queue_tail + 1) % EVENT_QUEUE_SIZE;
    if (next_tail == queue_head) {
        queue_head = (queue_head + 1) % EVENT_QUEUE_SIZE;
        dropped_events++;
    }

    memcpy(&event_queue[queue_tail], event, sizeof(struct security_event));
    queue_tail = next_tail;
    atomic_inc(&queue_count);
    total_events++;

    spin_unlock_irqrestore(&queue_lock, flags);

    // Schedule delayed dispatch (batch processing)
    if (atomic_read(&g_dispatcher->running)) {
        queue_delayed_work(g_dispatcher->workqueue, &g_dispatcher->dispatch_work,
                          msecs_to_jiffies(100));
    }

    return 0;
}

// ============================================================================
// Event Subscription Functions
// ============================================================================

int subscribe_to_events(const char *subscriber_name,
                       void (*callback)(struct security_event *),
                       uint32_t event_mask)
{
    struct event_subscriber *sub;
    unsigned long flags;

    if (!subscriber_name || !callback)
        return -EINVAL;

    if (subscriber_count >= MAX_SUBSCRIBERS) {
        pr_warn("RootShield: Maximum subscribers reached\n");
        return -ENOSPC;
    }

    sub = kzalloc(sizeof(*sub), GFP_KERNEL);
    if (!sub)
        return -ENOMEM;

    sub->name = subscriber_name;
    sub->callback = callback;
    sub->subscribed_events = event_mask;
    spin_lock_init(&sub->lock);
    atomic_set(&sub->active, 1);
    INIT_LIST_HEAD(&sub->list);

    spin_lock_irqsave(&subscriber_lock, flags);
    list_add_tail(&sub->list, &subscriber_list);
    subscriber_count++;
    spin_unlock_irqrestore(&subscriber_lock, flags);

    pr_info("RootShield: Subscriber '%s' registered (mask: 0x%x)\n",
            subscriber_name, event_mask);
    return 0;
}

int unsubscribe_from_events(const char *subscriber_name)
{
    struct event_subscriber *sub, *tmp;
    unsigned long flags;
    int found = 0;

    if (!subscriber_name)
        return -EINVAL;

    spin_lock_irqsave(&subscriber_lock, flags);
    list_for_each_entry_safe(sub, tmp, &subscriber_list, list) {
        if (strcmp(sub->name, subscriber_name) == 0) {
            list_del(&sub->list);
            kfree(sub);
            subscriber_count--;
            found = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&subscriber_lock, flags);

    if (found) {
        pr_info("RootShield: Subscriber '%s' unregistered\n", subscriber_name);
        return 0;
    }

    return -ENOENT;
}

// ============================================================================
// Event Dispatch Worker
// ============================================================================

static void dispatch_to_subscribers(struct security_event *event)
{
    struct event_subscriber *sub;
    unsigned long flags;

    spin_lock_irqsave(&subscriber_lock, flags);
    list_for_each_entry(sub, &subscriber_list, list) {
        if (!atomic_read(&sub->active))
            continue;

        // Check if subscriber is interested in this event type
        if (sub->subscribed_events & (1 << event->type)) {
            // Call subscriber callback (outside spinlock for safety)
            spin_unlock_irqrestore(&subscriber_lock, flags);
            sub->callback(event);
            spin_lock_irqsave(&subscriber_lock, flags);
        }
    }
    spin_unlock_irqrestore(&subscriber_lock, flags);
}

static void event_dispatch_worker(struct work_struct *work)
{
    struct security_event event;
    unsigned long flags;
    int events_processed = 0;
    const int max_batch = 16; // Process up to 16 events per batch

    while (events_processed < max_batch && atomic_read(&queue_count) > 0) {
        spin_lock_irqsave(&queue_lock, flags);

        if (queue_head == queue_tail) {
            spin_unlock_irqrestore(&queue_lock, flags);
            break;
        }

        // Dequeue event
        memcpy(&event, &event_queue[queue_head], sizeof(struct security_event));
        queue_head = (queue_head + 1) % EVENT_QUEUE_SIZE;
        atomic_dec(&queue_count);

        spin_unlock_irqrestore(&queue_lock, flags);

        // Dispatch to subscribers
        dispatch_to_subscribers(&event);

        processed_events++;
        events_processed++;
    }

    // Reschedule if more events pending
    if (atomic_read(&queue_count) > 0 && atomic_read(&g_dispatcher->running)) {
        queue_delayed_work(g_dispatcher->workqueue, &g_dispatcher->dispatch_work,
                          msecs_to_jiffies(10));
    }
}

// ============================================================================
// Event Processing Functions
// ============================================================================

int process_pending_events(void)
{
    if (!g_dispatcher)
        return -EINVAL;

    // Force immediate processing
    event_dispatch_worker(&g_dispatcher->dispatch_work.work);
    return 0;
}

int get_pending_event_count(void)
{
    return atomic_read(&queue_count);
}

// ============================================================================
// Event Statistics
// ============================================================================

void get_event_stats(uint64_t *total, uint64_t *processed, uint64_t *dropped)
{
    if (total)
        *total = total_events;
    if (processed)
        *processed = processed_events;
    if (dropped)
        *dropped = dropped_events;
}

// ============================================================================
// Utility Functions
// ============================================================================

struct security_event *create_security_event(event_type_t type,
                                             event_severity_t severity,
                                             const char *source)
{
    struct security_event *event;

    event = kzalloc(sizeof(*event), GFP_KERNEL);
    if (!event)
        return NULL;

    event->type = type;
    event->severity = severity;
    event->source = source;
    event->timestamp = ktime_get_real_ns();
    event->pid = task_pid_nr(current);
    event->uid = current_uid().val;
    event->gid = current_gid().val;
    strncpy(event->comm, current->comm, sizeof(event->comm) - 1);

    return event;
}

void destroy_security_event(struct security_event *event)
{
    if (event) {
        if (event->data)
            kfree(event->data);
        kfree(event);
    }
}

int copy_security_event(struct security_event *dst, const struct security_event *src)
{
    if (!dst || !src)
        return -EINVAL;

    memcpy(dst, src, sizeof(struct security_event));

    // Deep copy data if present
    if (src->data && src->data_size > 0) {
        dst->data = kmalloc(src->data_size, GFP_KERNEL);
        if (!dst->data)
            return -ENOMEM;
        memcpy(dst->data, src->data, src->data_size);
    }

    return 0;
}

// ============================================================================
// Event Debugging
// ============================================================================

static bool event_debugging = false;

void dump_event(const struct security_event *event)
{
    if (!event)
        return;

    pr_info("RootShield Event: id=%llu, type=%d, severity=%d, source=%s\n",
            event->id, event->type, event->severity, event->source);
    pr_info("  pid=%u, uid=%u, comm=%s, path=%s\n",
            event->pid, event->uid, event->comm, event->path);
}

void enable_event_debugging(bool enable)
{
    event_debugging = enable;
    pr_info("RootShield: Event debugging %s\n", enable ? "enabled" : "disabled");
}

// Export symbols for other modules
EXPORT_SYMBOL(init_event_system);
EXPORT_SYMBOL(exit_event_system);
EXPORT_SYMBOL(publish_event);
EXPORT_SYMBOL(publish_event_async);
EXPORT_SYMBOL(subscribe_to_events);
EXPORT_SYMBOL(unsubscribe_from_events);
EXPORT_SYMBOL(create_security_event);
EXPORT_SYMBOL(destroy_security_event);
EXPORT_SYMBOL(get_event_stats);
