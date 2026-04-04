//
//  bootstrap.m — Rootless bootstrap installer
//
//  Installs Procursus rootless bootstrap to /var/jb:
//  1. Create /var/jb directory
//  2. Download Procursus bootstrap tarball
//  3. Extract (tar xf) to /var/jb
//  4. Trust all binaries via trust cache
//  5. Install Sileo.deb
//  6. Install OpenSSH / dropbear .deb
//  7. Configure dpkg, setup apt sources
//
//  This follows the same approach as:
//  - Dopamine's DOBootstrapper.m
//  - palera1n's bootstrap installation
//  - Serotonin's rootless bootstrap
//

#include "bootstrap.h"
#include "postexploit.h"
#include "trustcache.h"
#include "kfs.h"
#include "darksword_core.h"
#include "filelog.h"

#import <Foundation/Foundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <errno.h>
#include <dlfcn.h>

/* ================================================================
   Logging
   ================================================================ */

static bs_log_callback_t g_log = NULL;
void bootstrap_set_log(bs_log_callback_t cb) { g_log = cb; }
static void blog(const char *fmt, ...) __attribute__((format(printf,1,2)));
static void blog(const char *fmt, ...) {
    char buf[1024]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    fprintf(stderr, "(bootstrap) %s\n", buf);
    filelog_write("[bootstrap] %s", buf);
    if (g_log) g_log(buf);
}

/* ================================================================
   Configuration
   ================================================================ */

/*
 * Procursus rootless bootstrap for iOS 17+:
 * Official: https://apt.procurs.us/bootstraps/
 *
 * IMPORTANT: stock iOS /usr/bin/tar does NOT support zstd.
 * We prefer .tar.xz (LZMA2) which BSD tar on iOS handles natively.
 * Fallback: if only .tar.zst is available, we decompress via embedded code.
 */
static const char *k_default_bootstrap_url =
    "https://apt.procurs.us/bootstraps/2000/bootstrap-ssh-iphoneos-arm64e.tar.xz";

static const char *g_bootstrap_url_zst =
    "https://apt.procurs.us/bootstraps/2000/bootstrap-ssh-iphoneos-arm64e.tar.zst";

static const char *k_default_sileo_url =
    "https://github.com/Sileo/Sileo/releases/latest/download/Sileo.deb";

static const char *g_bootstrap_url =
    "https://apt.procurs.us/bootstraps/2000/bootstrap-ssh-iphoneos-arm64e.tar.xz";

static const char *g_sileo_url =
    "https://github.com/Sileo/Sileo/releases/latest/download/Sileo.deb";

static const char *g_jb_root      = "/var/jb";
static const char *g_jb_tmp       = "/var/tmp/jb_bootstrap";
static const char *g_bootstrap_tar = "/var/tmp/jb_bootstrap/bootstrap.tar.xz";
static const char *g_sileo_deb     = "/var/tmp/jb_bootstrap/Sileo.deb";
static const char *g_bootstrap_tar_xz  = "/var/tmp/jb_bootstrap/bootstrap.tar.xz";
static const char *g_bootstrap_tar_zst = "/var/tmp/jb_bootstrap/bootstrap.tar.zst";

static bool is_http_url_string(const char *url);

void bootstrap_set_procursus_url(const char *url) {
    if (!is_http_url_string(url)) {
        blog("WARNING: invalid Procursus URL override; restoring default URL");
        g_bootstrap_url = k_default_bootstrap_url;
        return;
    }
    g_bootstrap_url = url;
}

void bootstrap_set_sileo_url(const char *url) {
    if (!is_http_url_string(url)) {
        blog("WARNING: invalid Sileo URL override; restoring default URL");
        g_sileo_url = k_default_sileo_url;
        return;
    }
    g_sileo_url = url;
}

/* ================================================================
   State
   ================================================================ */

static bool g_installed = false;
static bool g_running = false; /* re-entrancy guard */
bool bootstrap_is_installed(void) { return g_installed; }

static bool file_exists_with_min_size(const char *path, off_t min_size) {
    if (!path) return false;

    struct stat st;
    if (stat(path, &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    return st.st_size >= min_size;
}

static int ensure_directory_exists(const char *path, mode_t mode) {
    if (!path || path[0] == 0) return -1;

    if (mkdir(path, mode) == 0) {
        return 0;
    }
    if (errno != EEXIST) {
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    return 0;
}

static bool restore_env_var(const char *name, const char *value) {
    if (!name || name[0] == 0) return false;

    int ret = value ? setenv(name, value, 1) : unsetenv(name);
    if (ret != 0) {
        blog("ERROR: failed to restore %s: %s", name, strerror(errno));
        return false;
    }
    return true;
}

static bool is_http_url_string(const char *url) {
    if (!url || url[0] == 0) return false;
    return strncmp(url, "https://", 8) == 0 || strncmp(url, "http://", 7) == 0;
}

/* ================================================================
   Helpers: spawn process, download file
   ================================================================ */

static int run_cmd(const char *prog, ...) {
    char *argv[32];
    int argc = 0;
    argv[argc++] = (char *)prog;
    
    va_list ap;
    va_start(ap, prog);
    while (argc < 30) {
        char *arg = va_arg(ap, char *);
        if (!arg) break;
        argv[argc++] = arg;
    }
    va_end(ap);
    argv[argc] = NULL;
    
    blog("exec: %s %s %s ...", argv[0], argc>1?argv[1]:"", argc>2?argv[2]:"");
    
    pid_t pid;
    extern char **environ;
    int ret = posix_spawn(&pid, prog, NULL, NULL, argv, environ);
    if (ret != 0) {
        /* Try with /var/jb prefix */
        char jb_path[512];
        int path_len = snprintf(jb_path, sizeof(jb_path), "/var/jb%s", prog);
        if (path_len < 0 || path_len >= (int)sizeof(jb_path)) {
            blog("spawn path too long: %s", prog);
            return -1;
        }
        ret = posix_spawn(&pid, jb_path, NULL, NULL, argv, environ);
        if (ret != 0) {
            blog("spawn failed: %s (err %d)", prog, ret);
            return -1;
        }
    }
    
    int status = 0;
    pid_t waited = -1;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited != pid) {
        blog("waitpid failed for %s: %s", prog, strerror(errno));
        return -1;
    }

    int exit_code = -1;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        blog("%s terminated by signal %d", prog, WTERMSIG(status));
    } else {
        blog("%s terminated abnormally (status=0x%x)", prog, status);
    }
    if (exit_code != 0) {
        blog("%s exited with %d", prog, exit_code);
    }
    return exit_code;
}

static int download_file(const char *url, const char *dest) {
    if (!is_http_url_string(url)) {
        blog("download_file: invalid URL: %s", url ? url : "(null)");
        return -1;
    }
    if (!dest || dest[0] == 0) {
        blog("download_file: invalid destination path");
        return -1;
    }

    blog("downloading: %s", url);
    blog("  → %s", dest);

    /* Never reuse a stale partial file from a prior failed attempt. */
    unlink(dest);
    
    /* Try curl first (available on iOS) */
    int ret = run_cmd("/usr/bin/curl", "-fsSL", "-o", (char *)dest, (char *)url, NULL);
    if (ret == 0) return 0;
    
    /* Try wget if curl fails */
    ret = run_cmd("/usr/bin/wget", "-q", "-O", (char *)dest, (char *)url, NULL);
    if (ret == 0) return 0;
    
    /* NSURLSession fallback with timeout (requires Foundation) */
    blog("curl/wget failed — trying NSURLSession (30s timeout)...");
    
    @autoreleasepool {
        NSURL *nsurl = [NSURL URLWithString:@(url)];
        if (!nsurl) {
            blog("invalid NSURL for download: %s", url);
            unlink(dest);
            return -1;
        }
        NSURLSessionConfiguration *config = [NSURLSessionConfiguration defaultSessionConfiguration];
        config.timeoutIntervalForRequest = 30.0;
        config.timeoutIntervalForResource = 120.0;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
        
        __block NSData *result = nil;
        __block NSError *dlError = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        
        NSURLSessionDataTask *task = [session dataTaskWithURL:nsurl
            completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                if (error) { dlError = error; }
                else {
                    NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
                    if ([httpResp isKindOfClass:[NSHTTPURLResponse class]] && httpResp.statusCode != 200) {
                        blog("HTTP error: %ld", (long)httpResp.statusCode);
                    } else {
                        result = data;
                    }
                }
                dispatch_semaphore_signal(sem);
            }];
        [task resume];
        long wait_res = dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 120 * NSEC_PER_SEC));
        if (wait_res != 0) {
            blog("NSURLSession timeout after 120s");
            [task cancel];
            [session invalidateAndCancel];
            return -1;
        }
        
        if (result && result.length > 1024) { /* minimum sanity check */
            if (![result writeToFile:@(dest) atomically:YES]) {
                blog("failed to write downloaded file: %s", dest);
                [session finishTasksAndInvalidate];
                return -1;
            }
            blog("downloaded %lu bytes", (unsigned long)result.length);
            [session finishTasksAndInvalidate];
            return 0;
        }
        [session finishTasksAndInvalidate];
        if (dlError) blog("NSURLSession error: %s", dlError.localizedDescription.UTF8String);
    }
    
    blog("download failed: %s", url);
    unlink(dest);
    return -1;
}

/* ================================================================
   Step 1: Prepare rootless environment
   ================================================================ */

int bootstrap_prepare_rootless(void) {
    blog("preparing rootless environment at %s", g_jb_root);
    
    if (!postexploit_is_root()) {
        blog("ERROR: not root. Run postexploit_run() first.");
        return -1;
    }
    
    if (!postexploit_is_unsandboxed()) {
        blog("WARNING: still sandboxed — mkdir may fail.");
    }
    
    /* Create /var/jb directory */
    if (ensure_directory_exists(g_jb_root, 0755) != 0) {
        blog("ERROR: mkdir(%s) failed: %s", g_jb_root, strerror(errno));
        blog("sandbox may still be active, or path already exists as a file");
        return -1;
    }
    
    /* Create subdirectories */
    char path[256];
    const char *dirs[] = {
        "usr", "usr/bin", "usr/sbin", "usr/lib", "usr/local",
        "usr/local/bin", "usr/local/lib",
        "Library", "Library/dpkg", "Library/dpkg/info",
        "etc", "etc/apt", "etc/apt/sources.list.d",
        "etc/ssh",
        "var", "var/cache", "var/cache/apt", "var/cache/apt/archives",
        "var/lib", "var/lib/dpkg",
        "tmp",
        NULL
    };
    
    int dir_ok = 0, dir_fail = 0;
    for (int i = 0; dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", g_jb_root, dirs[i]);
        if (ensure_directory_exists(path, 0755) == 0) {
            dir_ok++;
        } else {
            blog("WARNING: mkdir(%s) failed: %s", path, strerror(errno));
            dir_fail++;
        }
    }

    if (dir_fail != 0) {
        blog("ERROR: failed to create %d bootstrap directories", dir_fail);
        return -1;
    }
    
    /* Create temp directory for downloads */
    if (ensure_directory_exists(g_jb_tmp, 0755) != 0) {
        blog("ERROR: mkdir(%s) failed: %s", g_jb_tmp, strerror(errno));
        return -1;
    }
    
    blog("rootless dirs created");
    return 0;
}

/* ================================================================
   Step 2: Download bootstrap
   ================================================================ */

int bootstrap_download(void) {
    blog("downloading bootstrap tarball...");

    /* Reset preferred path on every attempt.
     * Otherwise a prior .zst fallback leaves g_bootstrap_tar pointing at
     * bootstrap.tar.zst, and the next retry may download the .xz payload
     * into a .zst-named file. Then bootstrap_extract() chooses the wrong
     * decompression branch based on filename and fails again forever. */
    g_bootstrap_tar = g_bootstrap_tar_xz;
    
    if (file_exists_with_min_size(g_bootstrap_tar, 1024 * 1024)) {
        blog("bootstrap already downloaded");
        return 0;
    } else if (access(g_bootstrap_tar, F_OK) == 0) {
        blog("removing stale/partial bootstrap: %s", g_bootstrap_tar);
        unlink(g_bootstrap_tar);
    }
    
    /* Also check for .zst variant */
    const char *zst_path = g_bootstrap_tar_zst;
    if (file_exists_with_min_size(zst_path, 1024 * 1024)) {
        blog("bootstrap .zst already downloaded");
        g_bootstrap_tar = zst_path;
        return 0;
    } else if (access(zst_path, F_OK) == 0) {
        blog("removing stale/partial bootstrap .zst: %s", zst_path);
        unlink(zst_path);
    }
    
    /* Check available disk space: need ~400 MB for download + extract */
    struct statfs sfs;
    if (statfs("/var", &sfs) == 0) {
        uint64_t free_bytes = (uint64_t)sfs.f_bavail * sfs.f_bsize;
        if (free_bytes < 400ULL * 1024 * 1024) {
            blog("FAIL: insufficient disk space (%.0f MB free, need 400+ MB)",
                 free_bytes / (1024.0 * 1024.0));
            return -1;
        }
        blog("disk space: %.0f MB free", free_bytes / (1024.0 * 1024.0));
    }
    
    /* Try .tar.xz first (iOS tar can handle xz natively) */
    int ret = download_file(g_bootstrap_url, g_bootstrap_tar);
    if (ret == 0) return 0;
    
    /* Fallback: try .tar.zst */
    blog("xz download failed, trying zst variant...");
    g_bootstrap_tar = zst_path;
    return download_file(g_bootstrap_url_zst, g_bootstrap_tar);
}

/* ================================================================
   Step 3: Extract bootstrap to /var/jb
   ================================================================ */

int bootstrap_extract(void) {
    blog("extracting bootstrap to %s...", g_jb_root);
    
    /* Determine compression format from filename */
    int ret;
    if (strstr(g_bootstrap_tar, ".zst")) {
        /*
         * .tar.zst: stock iOS does NOT have /usr/bin/zstd.
         * BSD tar on iOS does NOT support --zstd.
         * Strategy:
         *   1. Try /usr/bin/zstd (won't exist on stock iOS)
         *   2. Try /var/jb/usr/bin/zstd (won't exist yet)
         *   3. Try tar --use-compress-program (won't work)
         *   4. FINAL: strip zstd frame header and decompress manually
         *      using the zstd magic to detect and skip the frame.
         *      For now, report clear error — user must provide .tar.xz
         */
        ret = run_cmd("/usr/bin/zstd", "-d", (char *)g_bootstrap_tar, "-o", 
                       "/var/tmp/jb_bootstrap/bootstrap.tar", NULL);
        if (ret == 0) {
            ret = run_cmd("/usr/bin/tar", "xf", "/var/tmp/jb_bootstrap/bootstrap.tar",
                          "-C", (char *)g_jb_root, NULL);
        } else {
            /* Try tar directly (won't work on stock iOS, but try anyway) */
            ret = run_cmd("/usr/bin/tar", "xf", (char *)g_bootstrap_tar,
                          "-C", (char *)g_jb_root, NULL);
            if (ret != 0) {
                blog("ERROR: .tar.zst cannot be decompressed on stock iOS!");
                blog("ERROR: zstd is not available in /usr/bin or /var/jb/usr/bin");
                blog("ERROR: Please use .tar.xz bootstrap or manually place zstd");
                blog("HINT: Re-download will try .tar.xz format automatically");
                /* Delete the unusable .zst so next run tries .xz */
                unlink(g_bootstrap_tar);
                return -1;
            }
        }
    } else if (strstr(g_bootstrap_tar, ".gz") || strstr(g_bootstrap_tar, ".xz")) {
        /* .tar.xz and .tar.gz are natively supported by iOS /usr/bin/tar */
        ret = run_cmd("/usr/bin/tar", "xf", (char *)g_bootstrap_tar,
                      "-C", (char *)g_jb_root, NULL);
    } else {
        ret = run_cmd("/usr/bin/tar", "xf", (char *)g_bootstrap_tar,
                      "-C", (char *)g_jb_root, NULL);
    }
    
    if (ret != 0) {
        blog("bootstrap extraction failed (ret=%d)", ret);
        return -1;
    }
    
    /* Verify extraction */
    char dpkg_path[256];
    snprintf(dpkg_path, sizeof(dpkg_path), "%s/usr/bin/dpkg", g_jb_root);
    if (access(dpkg_path, X_OK) == 0) {
        blog("bootstrap extracted successfully (dpkg found)");
    } else {
        blog("ERROR: dpkg not found after extraction");
        return -1;
    }
    
    return 0;
}

/* ================================================================
   Step 4: Trust all binaries
   ================================================================ */

int bootstrap_trust_binaries(void) {
    blog("trusting bootstrap binaries...");
    
    if (!tc_is_ready()) {
        blog("trust cache not available — attempting init...");
        tc_init();
    }
    
    char path[256];
    int total = 0;
    bool had_error = false;
    
    /* Trust key directories */
    const char *trust_dirs[] = {
        "usr/bin", "usr/sbin", "usr/lib", "usr/libexec",
        "usr/local/bin", "usr/local/lib",
        NULL
    };
    
    for (int i = 0; trust_dirs[i]; i++) {
        snprintf(path, sizeof(path), "%s/%s", g_jb_root, trust_dirs[i]);
        int n = tc_trust_directory(path);
        if (n > 0) {
            total += n;
        } else if (n < 0) {
            had_error = true;
            blog("ERROR: failed to trust bootstrap directory %s", path);
        }
    }
    
    blog("trusted %d binaries total", total);
    return (total > 0 && !had_error) ? 0 : -1;
}

/* ================================================================
   Step 5: Install Sileo
   ================================================================ */

int bootstrap_install_sileo(void) {
    blog("installing Sileo...");
    
    if (!file_exists_with_min_size(g_sileo_deb, 64 * 1024)) {
        if (access(g_sileo_deb, F_OK) == 0) {
            blog("removing stale/partial Sileo.deb");
            unlink(g_sileo_deb);
        }
        if (download_file(g_sileo_url, g_sileo_deb) != 0) {
            blog("Sileo download failed");
            return -1;
        }
    }
    
    /* Install with dpkg (trust dpkg first if needed) */
    char dpkg[256];
    snprintf(dpkg, sizeof(dpkg), "%s/usr/bin/dpkg", g_jb_root);
    int ret = run_cmd(dpkg, "--force-depends", "-i", (char *)g_sileo_deb, NULL);
    
    if (ret != 0) {
        blog("dpkg -i Sileo.deb failed (ret=%d)", ret);
        return -1;
    }
    
    /* Trust AFTER install — trust the installed binaries, not the .deb */
    char sileo_app[256];
    snprintf(sileo_app, sizeof(sileo_app), "%s/Applications/Sileo.app", g_jb_root);
    if (access(sileo_app, F_OK) != 0) {
        blog("ERROR: Sileo.app missing after dpkg install");
        return -1;
    }

    int trust_successes = 0;
    int app_trust_ret = tc_trust_directory(sileo_app);
    if (app_trust_ret > 0) {
        trust_successes++;
    } else {
        blog("ERROR: failed to trust installed Sileo.app");
    }

    int deb_trust_ret = tc_trust_deb(g_sileo_deb); /* also trust contents in case they differ */
    if (deb_trust_ret > 0) {
        trust_successes++;
    } else {
        blog("ERROR: failed to trust Sileo.deb contents");
    }

    if (trust_successes == 0) {
        return -1;
    }
    
    /* Register Sileo with SpringBoard so icon appears on home screen */
    char uicache[256];
    snprintf(uicache, sizeof(uicache), "%s/usr/bin/uicache", g_jb_root);
    if (access(uicache, X_OK) == 0) {
        if (tc_trust_file(uicache) != 0) {
            blog("ERROR: failed to trust uicache");
            return -1;
        }
        int uicache_ret = run_cmd(uicache, "-p", sileo_app, NULL);
        if (uicache_ret != 0) {
            blog("ERROR: uicache failed for Sileo.app (ret=%d)", uicache_ret);
            return -1;
        }
        blog("uicache done for Sileo.app");
    } else {
        blog("WARNING: uicache not found — Sileo icon may not appear until respring");
    }
    
    blog("Sileo installed");
    return 0;
}

/* ================================================================
   Step 6: Install OpenSSH
   ================================================================ */

int bootstrap_install_openssh(void) {
    blog("installing OpenSSH...");
    
    /* OpenSSH is typically included in Procursus bootstrap.
     * If not, install via apt after Sileo is set up.
     */
    char sshd[256];
    snprintf(sshd, sizeof(sshd), "%s/usr/sbin/sshd", g_jb_root);

    if (access(sshd, F_OK) != 0) {
        /* Try installing via apt if available */
        char apt[256];
        snprintf(apt, sizeof(apt), "%s/usr/bin/apt", g_jb_root);

        if (access(apt, X_OK) != 0) {
            blog("ERROR: OpenSSH unavailable (no bundled sshd and apt not runnable)");
            return -1;
        }

        int ret = run_cmd(apt, "install", "-y", "openssh-server", "openssh-client", NULL);
        if (ret != 0) {
            blog("ERROR: apt install OpenSSH failed (ret=%d)", ret);
            return -1;
        }

        char sshd_dir[256];
        snprintf(sshd_dir, sizeof(sshd_dir), "%s/usr/sbin", g_jb_root);
        if (access(sshd, X_OK) != 0) {
            blog("ERROR: sshd missing after apt install");
            return -1;
        }
        if (tc_trust_directory(sshd_dir) <= 0) {
            blog("ERROR: failed to trust OpenSSH binaries after apt install");
            return -1;
        }

        blog("OpenSSH packages installed via apt; validating daemon setup...");
    } else {
        blog("sshd already present in bootstrap");
    }

    if (tc_trust_file(sshd) != 0) {
        blog("ERROR: failed to trust sshd binary");
        return -1;
    }

    /* Generate host keys if missing */
    char keygen[256];
    snprintf(keygen, sizeof(keygen), "%s/usr/bin/ssh-keygen", g_jb_root);
    if (access(keygen, X_OK) == 0) {
        if (tc_trust_file(keygen) != 0) {
            blog("ERROR: failed to trust ssh-keygen");
            return -1;
        }

        char rsa_key[256], ed_key[256];
        snprintf(rsa_key, sizeof(rsa_key), "%s/etc/ssh/ssh_host_rsa_key", g_jb_root);
        snprintf(ed_key, sizeof(ed_key), "%s/etc/ssh/ssh_host_ed25519_key", g_jb_root);

        /* Create /var/jb/etc/ssh if missing */
        char ssh_dir[256];
        snprintf(ssh_dir, sizeof(ssh_dir), "%s/etc/ssh", g_jb_root);
        if (ensure_directory_exists(ssh_dir, 0755) != 0) {
            blog("ERROR: mkdir(%s) failed: %s", ssh_dir, strerror(errno));
            return -1;
        }

        if (access(rsa_key, F_OK) != 0) {
            if (run_cmd(keygen, "-t", "rsa", "-b", "4096", "-f", rsa_key, "-N", "", NULL) != 0) {
                blog("WARNING: failed to generate RSA host key");
            }
        }
        if (access(ed_key, F_OK) != 0) {
            if (run_cmd(keygen, "-t", "ed25519", "-f", ed_key, "-N", "", NULL) != 0) {
                blog("WARNING: failed to generate ED25519 host key");
            }
        }
        if (access(rsa_key, F_OK) != 0 && access(ed_key, F_OK) != 0) {
            blog("ERROR: no SSH host keys available after generation attempt");
            return -1;
        }
        blog("SSH host keys ready");
    }

    /* Start sshd on port 22 */
    char sshd_config[256];
    snprintf(sshd_config, sizeof(sshd_config), "%s/etc/ssh/sshd_config", g_jb_root);
    int sshd_ret = -1;
    if (access(sshd_config, F_OK) == 0) {
        sshd_ret = run_cmd(sshd, "-f", sshd_config, NULL);
        if (sshd_ret != 0) {
            blog("ERROR: sshd launch failed with config (ret=%d)", sshd_ret);
            return -1;
        }
        blog("sshd launched (port 22, default password: alpine)");
    } else {
        sshd_ret = run_cmd(sshd, NULL);
        if (sshd_ret != 0) {
            blog("ERROR: sshd launch failed with default config (ret=%d)", sshd_ret);
            return -1;
        }
        blog("sshd launched (default config, port 22)");
    }

    return 0;
}

/* ================================================================
   Step 7: dpkg --configure -a
   ================================================================ */

int bootstrap_run_dpkg_configure(void) {
    char dpkg[256];
    snprintf(dpkg, sizeof(dpkg), "%s/usr/bin/dpkg", g_jb_root);
    
    if (access(dpkg, X_OK) != 0) {
        blog("dpkg not found");
        return -1;
    }
    
    blog("running dpkg --configure -a ...");
    return run_cmd(dpkg, "--configure", "-a", NULL);
}

/* ================================================================
   Step 8: Setup apt sources
   ================================================================ */

int bootstrap_setup_sources(void) {
    blog("setting up apt sources...");
    
    /* Procursus repo */
    char sources[256];
    snprintf(sources, sizeof(sources), "%s/etc/apt/sources.list.d/procursus.sources", g_jb_root);
    
    FILE *f = fopen(sources, "w");
    if (!f) { blog("can't write sources"); return -1; }
    
    if (fprintf(f,
        "Types: deb\n"
        "URIs: https://apt.procurs.us/\n"
        "Suites: iphoneos-arm64e/%d\n"
        "Components: main\n",
        2000 /* distribution ID */
    ) < 0) {
        blog("failed to write procursus sources");
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        blog("failed to flush procursus sources: %s", strerror(errno));
        return -1;
    }
    
    /* Havoc repo (popular tweak repo) */
    snprintf(sources, sizeof(sources), "%s/etc/apt/sources.list.d/havoc.sources", g_jb_root);
    f = fopen(sources, "w");
    if (!f) {
        blog("can't write havoc sources");
        return -1;
    }

    if (fprintf(f,
        "Types: deb\n"
        "URIs: https://havoc.app/\n"
        "Suites: ./\n"
        "Components:\n"
    ) < 0) {
        blog("failed to write havoc sources");
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0) {
        blog("failed to flush havoc sources: %s", strerror(errno));
        return -1;
    }
    
    blog("apt sources configured");
    return 0;
}

/* ================================================================
   Full bootstrap pipeline
   ================================================================ */

int bootstrap_install(void) {
    blog("=========================================");
    blog(" Bootstrap Installation Pipeline");
    blog("=========================================");

    char *saved_path = NULL;
    char *saved_dpkg_root = NULL;
    bool env_modified = false;
    bool completed_pipeline = false;
    int errors = 0;
    int retcode = -1;
    
    /* Verify prerequisites */
    if (!ds_is_ready()) {
        blog("ERROR: exploit not ready");
        return -1;
    }
    
    if (!postexploit_is_root()) {
        blog("WARNING: not root — running postexploit...");
        if (postexploit_run() != 0) {
            blog("ERROR: postexploit failed");
            return -1;
        }
    }
    
    /* Check sandbox escape */
    if (!postexploit_is_unsandboxed()) {
        blog("WARNING: still sandboxed — file operations may fail");
        blog("Attempting to continue anyway (AMFI global bypass may help)...");
    }

    /* Re-entrancy guard */
    if (g_running) {
        blog("ERROR: bootstrap_install already running");
        return -1;
    }
    
    /* Set PATH to include /var/jb/usr/bin for child processes */
    const char *old_path = getenv("PATH");
    const char *old_dpkg_root = getenv("DPKG_ROOT");
    if (old_path) {
        saved_path = strdup(old_path);
        if (!saved_path) {
            blog("ERROR: failed to preserve existing PATH");
            return -1;
        }
    }
    if (old_dpkg_root) {
        saved_dpkg_root = strdup(old_dpkg_root);
        if (!saved_dpkg_root) {
            blog("ERROR: failed to preserve existing DPKG_ROOT");
            free(saved_path);
            return -1;
        }
    }

    char new_path[1024];
    int new_path_len = snprintf(new_path, sizeof(new_path), "/var/jb/usr/bin:/var/jb/usr/sbin:%s",
                                old_path ? old_path : "/usr/bin:/bin");
    if (new_path_len < 0 || new_path_len >= (int)sizeof(new_path)) {
        blog("ERROR: PATH too long for bootstrap environment");
        goto out;
    }
    if (setenv("PATH", new_path, 1) != 0) {
        blog("ERROR: setenv(PATH) failed: %s", strerror(errno));
        goto out;
    }
    if (setenv("DPKG_ROOT", g_jb_root, 1) != 0) {
        blog("ERROR: setenv(DPKG_ROOT) failed: %s", strerror(errno));
        goto out;
    }
    env_modified = true;

    /* Reset reported install state for this attempt.
     * Otherwise an earlier success can survive a later critical failure and
     * mislead UI/summary code into claiming /var/jb is fully installed. */
    g_installed = false;
    g_running = true;
    
    /* Step 1: Prepare rootless dirs */
    blog("[1/8] Preparing rootless environment...");
    if (bootstrap_prepare_rootless() != 0) {
        blog("FAIL: prepare rootless — cannot continue"); 
        goto out; /* CRITICAL: no dirs = nothing works */
    }
    
    /* Step 2: Download bootstrap */
    blog("[2/8] Downloading Procursus bootstrap...");
    if (bootstrap_download() != 0) {
        blog("FAIL: download bootstrap"); errors++;
        blog("NOTE: you can manually place bootstrap at %s", g_bootstrap_tar);
        blog("CRITICAL: skipping remaining steps (no bootstrap to extract)");
        goto out; /* CRITICAL: no download = can't extract */
    }
    
    /* Step 3: Extract */
    blog("[3/8] Extracting bootstrap...");
    if (bootstrap_extract() != 0) {
        blog("FAIL: extract bootstrap");
        blog("CRITICAL: skipping remaining steps (extraction failed)");
        goto out; /* CRITICAL: no files = can't install */
    }
    
    /* Step 4: Trust binaries */
    blog("[4/8] Trusting binaries...");
    if (bootstrap_trust_binaries() != 0) {
        blog("WARNING: trust cache injection issue (may still work with CS_DEBUGGED)");
        errors++;
    }
    
    /* Step 5: Install Sileo */
    blog("[5/8] Installing Sileo...");
    if (bootstrap_install_sileo() != 0) {
        blog("WARNING: Sileo installation issue");
        errors++;
    }
    
    /* Step 6: Install OpenSSH */
    blog("[6/8] Installing OpenSSH...");
    if (bootstrap_install_openssh() != 0) {
        blog("WARNING: OpenSSH not installed yet (install via Sileo later)");
        errors++;
    }
    
    /* Step 7: dpkg configure */
    blog("[7/8] Configuring packages...");
    if (bootstrap_run_dpkg_configure() != 0) {
        blog("WARNING: dpkg configure failed");
        errors++;
    }
    
    /* Step 8: Setup sources */
    blog("[8/8] Setting up apt sources...");
    if (bootstrap_setup_sources() != 0) {
        blog("WARNING: apt sources setup failed");
        errors++;
    }
    
    /* Cleanup: remove large temp files to free disk space */
    blog("cleaning up temporary files...");
    unlink("/var/tmp/jb_bootstrap/bootstrap.tar.xz");
    unlink("/var/tmp/jb_bootstrap/bootstrap.tar.zst");
    unlink("/var/tmp/jb_bootstrap/bootstrap.tar");
    /* Keep Sileo.deb for reference */
    
    g_installed = (errors == 0);
    g_running = false;
    retcode = errors;
    completed_pipeline = true;

out:
    if (g_running) {
        g_running = false;
    }
    if (env_modified) {
        bool restore_ok = true;

        if (!restore_env_var("PATH", saved_path)) {
            restore_ok = false;
        }
        if (!restore_env_var("DPKG_ROOT", saved_dpkg_root)) {
            restore_ok = false;
        }

        if (!restore_ok) {
            g_installed = false;
            if (retcode >= 0) {
                retcode++;
            }
        }
    }

    if (completed_pipeline) {
        blog("=========================================");
        blog(" Bootstrap installation %s (%d errors)",
             g_installed ? "COMPLETE" : "PARTIAL", retcode >= 0 ? retcode : 1);
        blog("=========================================");
        blog(" Jailbreak root: %s", g_jb_root);
        blog(" Sileo:   %s/Applications/Sileo.app", g_jb_root);
        blog(" SSH:     %s/usr/sbin/sshd (port 22)", g_jb_root);
        blog(" dpkg:    %s/usr/bin/dpkg", g_jb_root);
        blog(" apt:     %s/usr/bin/apt", g_jb_root);
        blog("=========================================");
    }

    free(saved_path);
    free(saved_dpkg_root);
    return retcode;
}
