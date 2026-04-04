/*
 * darksword_core.h — Public API (matches rooootdev/lara darksword.h exactly)
 *
 * darksword kernel exploit: VFS race → physical OOB → ICMPv6 filter corruption
 * Original author: opa334 (PoC), rooootdev/ruter (lara implementation)
 */

#ifndef ds_h
#define ds_h

#include <stdint.h>
#include <stdbool.h>

typedef void (*ds_log_callback_t)(const char *message);

void     ds_set_log_callback(ds_log_callback_t callback);
void     ds_logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int      ds_run(void);
bool     ds_is_ready(void);

uint64_t ds_get_kernel_base(void);
uint64_t ds_get_kernel_slide(void);
uint64_t ds_kread64(uint64_t address);
uint32_t ds_kread32(uint64_t address);
bool     ds_kread64_checked(uint64_t address, uint64_t *value);
bool     ds_kread32_checked(uint64_t address, uint32_t *value);

void     ds_kwrite64(uint64_t address, uint64_t value);
void     ds_kwrite32(uint64_t address, uint32_t value);
void     ds_kread(uint64_t address, void *buffer, uint64_t size);
bool     ds_kread_checked(uint64_t address, void *buffer, uint64_t size);
void     ds_kwrite(uint64_t address, void *buffer, uint64_t size);

uint64_t ds_get_pcbinfo(void);
uint64_t ds_get_rw_socket_pcb(void);

/* Zone map boundaries discovered at runtime.
 * Returns 0 if discovery has not completed yet. */
uint64_t ds_get_zone_map_min(void);
uint64_t ds_get_zone_map_max(void);
/* Bug #225: safe lower bound skipping VM+RO submaps (per-CPU allocations).
 * Use this instead of zone_map_min when checking heap object pointers.
 * Reading from per-CPU zone elements causes kernel panic:
 *   "zone bound checks: address X is a per-cpu allocation" */
uint64_t ds_get_zone_safe_min(void);

/* Scoped relaxation for validated proc/allproc traversal. Calls may be nested. */
void     ds_enter_proc_read_scope(void);
void     ds_leave_proc_read_scope(void);
bool     ds_proc_scope_guard_tripped(void);
void     ds_reset_proc_scope_guard(void);

uint64_t ds_get_our_proc(void);
uint64_t ds_get_our_task(void);

#endif /* ds_h */
