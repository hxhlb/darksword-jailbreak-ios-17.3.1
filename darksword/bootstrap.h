//
//  bootstrap.h — Rootless bootstrap installer
//
//  Installs Procursus bootstrap (dpkg, apt, Sileo, OpenSSH)
//  to /var/jb (rootless jailbreak path).
//
//  Requires: kernel R/W, root credentials, sandbox escaped, trust cache.
//

#ifndef BOOTSTRAP_H
#define BOOTSTRAP_H

#include <stdbool.h>

// Full bootstrap installation pipeline
// Downloads and installs: Procursus bootstrap → Sileo → OpenSSH
int bootstrap_install(void);

// Individual steps
int bootstrap_prepare_rootless(void);       // Create /var/jb symlink + dirs
int bootstrap_download(void);               // Download bootstrap tarball
int bootstrap_extract(void);                // Extract to /var/jb
int bootstrap_trust_binaries(void);         // Trust all bootstrap binaries
int bootstrap_install_sileo(void);          // Install Sileo package manager
int bootstrap_install_openssh(void);        // Install OpenSSH (dropbear)
int bootstrap_run_dpkg_configure(void);     // dpkg --configure -a
int bootstrap_setup_sources(void);          // Add default apt sources

// State
bool bootstrap_is_installed(void);

// Configuration
void bootstrap_set_procursus_url(const char *url);
void bootstrap_set_sileo_url(const char *url);

typedef void (*bs_log_callback_t)(const char *msg);
void bootstrap_set_log(bs_log_callback_t cb);

#endif
