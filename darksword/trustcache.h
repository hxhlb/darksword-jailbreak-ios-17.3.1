//
//  trustcache.h — Static trust cache injection
//
//  iOS uses trust caches to whitelist CDHashes of binaries allowed to run.
//  This module injects CDHashes into the kernel trust cache so that
//  unsigned/sideloaded binaries (Sileo, OpenSSH, bootstrap) can execute.
//

#ifndef TRUSTCACHE_H
#define TRUSTCACHE_H

#include <stdint.h>
#include <stdbool.h>

// Initialize trust cache module (finds kernel trust cache list)
int tc_init(void);
bool tc_is_ready(void);

// Add a single CDHash (20 bytes) to the trust cache
int tc_add_cdhash(const uint8_t cdhash[20]);

// Add CDHash from a Mach-O file on disk
int tc_trust_file(const char *path);

// Add all Mach-O files in a directory tree (recursive)
int tc_trust_directory(const char *path);

// Trust a .deb package contents (extracts, trusts all binaries)
int tc_trust_deb(const char *deb_path);

typedef void (*tc_log_callback_t)(const char *msg);
void tc_set_log(tc_log_callback_t cb);

#endif
