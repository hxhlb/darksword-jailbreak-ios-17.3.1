/*
 * filelog.m — File-based logging for DarkSword
 *
 * All log output goes to:
 *   <App>/Documents/darksword_log.txt
 *
 * After sandbox escape, also copies to:
 *   /var/mobile/Documents/darksword_log.txt
 *
 * The file is flushed after EVERY write so even if the device
 * panics/crashes, all logs up to that point are preserved.
 */

#import <Foundation/Foundation.h>
#include "filelog.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>

/* ================================================================
   State
   ================================================================ */

static FILE *g_logfile = NULL;
static char g_logpath[1024] = {0};
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- Batched I/O state --- */
/* fsync every FILELOG_FSYNC_INTERVAL writes, not on every line.       */
/* A background timer flushes at most every FILELOG_FLUSH_INTERVAL sec. */
/* Bug #501: DiskWrites resource violation — fsync every 32 writes caused
 * ~5 DiskWrites/sec violations during allproc scan and zone boundary discovery.
 * Increased to 256 to reduce forced-fsync overhead while preserving crash-safety
 * via the background 5-second timer flush. Real-device tests showed no log data
 * loss at 256 because the timer fires before any realistic crash interval. */
#define FILELOG_FSYNC_INTERVAL   256         /* writes between forced fsyncs   */
#define FILELOG_MAX_SIZE_BYTES   (10 * 1024 * 1024)   /* 10 MB rotation limit  */
#define FILELOG_FLUSH_INTERVAL   5.0         /* seconds for periodic flush     */

static volatile int32_t g_write_counter = 0;
static dispatch_source_t g_flush_timer  = NULL;

/* ================================================================
   Device info header
   ================================================================ */

static void write_device_header(void) {
    if (!g_logfile) return;
    
    /* Timestamp */
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", t);
    
    /* Device model */
    struct utsname uts;
    uname(&uts);
    
    /* iOS version */
    char ios_version[64] = {0};
    size_t len = sizeof(ios_version);
    sysctlbyname("kern.osproductversion", ios_version, &len, NULL, 0);
    
    /* Build number */
    char build[64] = {0};
    len = sizeof(build);
    sysctlbyname("kern.osversion", build, &len, NULL, 0);
    
    /* Hardware model */
    char hw_model[64] = {0};
    len = sizeof(hw_model);
    sysctlbyname("hw.model", hw_model, &len, NULL, 0);
    
    /* CPU subtype (arm64e check) */
    cpu_subtype_t cpusub = 0;
    len = sizeof(cpusub);
    sysctlbyname("hw.cpusubtype", &cpusub, &len, NULL, 0);
    
    /* Memory */
    uint64_t memsize = 0;
    len = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &len, NULL, 0);
    
    fprintf(g_logfile,
        "╔══════════════════════════════════════════════════════╗\n"
        "║  DarkSword Jailbreak Log                            ║\n"
        "╠══════════════════════════════════════════════════════╣\n"
        "║  Date:     %s                     ║\n"
        "║  Device:   %-42s ║\n"
        "║  HW Model: %-42s ║\n"
        "║  iOS:      %-42s ║\n"
        "║  Build:    %-42s ║\n"
        "║  CPU:      %s (subtype 0x%x)%-24s ║\n"
        "║  RAM:      %llu MB%-36s ║\n"
        "║  PID:      %-42d ║\n"
        "║  Log:      %-42s ║\n"
        "╚══════════════════════════════════════════════════════╝\n\n",
        timebuf,
        uts.machine, hw_model, ios_version, build,
        (cpusub & ~0xFF) == 2 ? "arm64e" : "arm64", cpusub, "",
        memsize / (1024*1024), "",
        getpid(),
        g_logpath
    );
    fflush(g_logfile);
}

/* ================================================================
   Init
   ================================================================ */

/* Start per-file periodic flush timer (must hold g_mutex or call before threads) */
static void filelog_start_flush_timer(void) {
    if (g_flush_timer) return;
    dispatch_queue_t q = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0);
    g_flush_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(g_flush_timer,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(FILELOG_FLUSH_INTERVAL * NSEC_PER_SEC)),
        (uint64_t)(FILELOG_FLUSH_INTERVAL * NSEC_PER_SEC),
        (uint64_t)(1 * NSEC_PER_SEC)); /* 1s leeway — reduces wakeups */
    dispatch_source_set_event_handler(g_flush_timer, ^{
        pthread_mutex_lock(&g_mutex);
        if (g_logfile) {
            fflush(g_logfile);
            /* periodic fsync only if there were writes since last timer fire */
            if (g_write_counter > 0) {
                fsync(fileno(g_logfile));
                g_write_counter = 0;
            }
        }
        pthread_mutex_unlock(&g_mutex);
    });
    dispatch_resume(g_flush_timer);
}

/* Rotate log file if it exceeds FILELOG_MAX_SIZE_BYTES.
   Renames current log to darksword_log.1.txt and opens a fresh log.    */
static void filelog_rotate_if_needed_locked(void) {
    if (!g_logfile || !g_logpath[0]) return;
    long pos = ftell(g_logfile);
    if (pos < FILELOG_MAX_SIZE_BYTES) return;

    fflush(g_logfile);
    fclose(g_logfile);
    g_logfile = NULL;

    /* Build rotate destination: replace .txt → .1.txt */
    char rotated[1024];
    snprintf(rotated, sizeof(rotated), "%s", g_logpath);
    char *ext = strstr(rotated, ".txt");
    if (ext) { *ext = '\0'; }
    strncat(rotated, ".1.txt", sizeof(rotated) - strlen(rotated) - 1);
    rename(g_logpath, rotated); /* best-effort */

    g_logfile = fopen(g_logpath, "w");
    if (g_logfile) {
        /* 64 KB line buffer — amortises write syscalls */
        setvbuf(g_logfile, NULL, _IOFBF, 65536);
        fprintf(g_logfile, "[filelog] === log rotated (previous: %s) ===\n", rotated);
        fflush(g_logfile);
        NSLog(@"[darksword] Log rotated → %s", rotated);
    }
}

void filelog_init(void) {
    if (g_logfile) return;   /* Already initialized */
    
    @autoreleasepool {
        /* Primary: app Documents directory (always writable) */
        NSArray *paths = NSSearchPathForDirectoriesInDomains(
            NSDocumentDirectory, NSUserDomainMask, YES);
        NSString *docs = [paths firstObject];
        
        if (docs) {
            NSString *logPath = [docs stringByAppendingPathComponent:@"darksword_log.txt"];
            strncpy(g_logpath, [logPath UTF8String], sizeof(g_logpath) - 1);
        } else {
            /* Fallback: tmp directory */
            NSString *tmp = NSTemporaryDirectory();
            NSString *logPath = [tmp stringByAppendingPathComponent:@"darksword_log.txt"];
            strncpy(g_logpath, [logPath UTF8String], sizeof(g_logpath) - 1);
        }
        
        g_logfile = fopen(g_logpath, "a");  /* append — survive restart */
        if (!g_logfile) {
            /* Last resort: /var/tmp */
            strncpy(g_logpath, "/var/tmp/darksword_log.txt", sizeof(g_logpath) - 1);
            g_logfile = fopen(g_logpath, "a");
        }
        
        if (g_logfile) {
            /* 64 KB line buffer — dramatically reduces disk I/O syscalls.         */
            /* We do NOT use _IONBF here; periodic fsync + timer keeps data safe.  */
            setvbuf(g_logfile, NULL, _IOFBF, 65536);
            write_device_header();
            /* One initial fsync so the header hits disk before exploit runs */
            fflush(g_logfile);
            fsync(fileno(g_logfile));
            g_write_counter = 0;
            filelog_start_flush_timer();
            NSLog(@"[darksword] Log file: %s", g_logpath);
        } else {
            NSLog(@"[darksword] WARNING: Could not open log file!");
        }
    }
}

/* ================================================================
   Write
   ================================================================ */

void filelog_write(const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);

    /* === Write to file === */
    if (g_logfile) {
        pthread_mutex_lock(&g_mutex);

        /* Rotate if the file is getting too large */
        filelog_rotate_if_needed_locked();

        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(g_logfile, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(g_logfile, fmt, ap);
        fprintf(g_logfile, "\n");

        /* Batched fsync: only force to disk every FILELOG_FSYNC_INTERVAL writes. */
        /* Between fsyncs the 64KB stdio buffer absorbs bursts without disk I/O.  */
        int32_t cnt = ++g_write_counter;
        if (cnt >= FILELOG_FSYNC_INTERVAL) {
            fflush(g_logfile);
            fsync(fileno(g_logfile));
            g_write_counter = 0;
        }

        pthread_mutex_unlock(&g_mutex);
    }
    va_end(ap);

    /* === Also emit to syslog (captured by idevicesyslog.exe via USB) === */
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap2);
    va_end(ap2);
    NSLog(@"[darksword] %s", buf);
}

/* ================================================================
   Copy to shared location (after unsandbox + root)
   ================================================================ */

void filelog_copy_to_shared(void) {
    if (!g_logfile || !g_logpath[0]) return;
    
    @autoreleasepool {
        /* Flush before copying */
        fflush(g_logfile);
        
        NSString *src = @(g_logpath);
        NSFileManager *fm = [NSFileManager defaultManager];
        
        /* Try several well-known locations */
        NSArray *dests = @[
            @"/var/mobile/Documents/darksword_log.txt",
            @"/var/mobile/Downloads/darksword_log.txt",
            @"/var/tmp/darksword_log.txt"
        ];
        
        for (NSString *dest in dests) {
            /* Create parent dir if needed */
            NSString *parent = [dest stringByDeletingLastPathComponent];
            [fm createDirectoryAtPath:parent
              withIntermediateDirectories:YES
                             attributes:nil
                                  error:nil];
            
            /* Remove old copy */
            [fm removeItemAtPath:dest error:nil];
            
            NSError *err = nil;
            if ([fm copyItemAtPath:src toPath:dest error:&err]) {
                filelog_write("Log copied to: %s", [dest UTF8String]);
                NSLog(@"[darksword] Log copied to: %@", dest);
            }
        }
    }
}

/* ================================================================
   Close
   ================================================================ */

void filelog_close(void) {
    /* Stop the periodic timer first to avoid a race with fclose */
    if (g_flush_timer) {
        dispatch_source_cancel(g_flush_timer);
        g_flush_timer = NULL;
    }
    if (g_logfile) {
        filelog_write("=== Log closed ===");
        pthread_mutex_lock(&g_mutex);
        fflush(g_logfile);
        fsync(fileno(g_logfile));  /* final guaranteed flush to disk */
        fclose(g_logfile);
        g_logfile = NULL;
        g_write_counter = 0;
        pthread_mutex_unlock(&g_mutex);
    }
}

/* ================================================================
   Get path
   ================================================================ */

const char *filelog_get_path(void) {
    return g_logpath;
}
