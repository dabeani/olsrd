/* Minimal compatibility shim for platforms missing <sys/queue.h>
 * Provides singly-linked list macros used by the plugin. The real
 * <sys/queue.h> provides many macros; we only implement the tiny subset
 * needed by this plugin translation unit to build on restrictive targets.
 */
#ifndef SYS_QUEUE_COMPAT_H
#define SYS_QUEUE_COMPAT_H

/* simple singly-linked list implementation for portability */
struct slist_entry {
  struct slist_entry *next;
};

#define SLIST_HEAD(name, type) struct name { struct type *slh_first; }
#define SLIST_ENTRY(type) struct slist_entry

#define SLIST_INIT(head) do { (head)->slh_first = NULL; } while(0)
#define SLIST_INSERT_HEAD(head, elm, field) do { (elm)->field.next = (head)->slh_first; (head)->slh_first = (elm); } while(0)
#define SLIST_FIRST(head) ((head)->slh_first)
#define SLIST_FOREACH(var, head, field) for ((var) = (head)->slh_first; (var); (var) = (var)->field.next)

#endif /* SYS_QUEUE_COMPAT_H */
