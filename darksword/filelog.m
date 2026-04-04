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
        
        g_logfile = fopen(g_logpath, "w");
        if (!g_logfile) {
            /* Last resort: /var/tmp */
            strncpy(g_logpath, "/var/tmp/darksword_log.txt", sizeof(g_logpath) - 1);
            g_logfile = fopen(g_logpath, "w");
        }
        
        if (g_logfile) {
            /* Disable buffering — flush every write */
            setvbuf(g_logfile, NULL, _IONBF, 0);
            write_device_header();
            /* fsync to guarantee header is on disk */
            fsync(fileno(g_logfile));
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
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(g_logfile, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);
        vfprintf(g_logfile, fmt, ap);
        fprintf(g_logfile, "\n");
        fflush(g_logfile);
        fsync(fileno(g_logfile));  /* force to disk — survives kernel panic */
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
    if (g_logfile) {
        filelog_write("=== Log closed ===");
        fflush(g_logfile);
        fclose(g_logfile);
        g_logfile = NULL;
    }
}

/* ================================================================
   Get path
   ================================================================ */

const char *filelog_get_path(void) {
    return g_logpath;
}
