/*
 * filelog.h — File-based logging for DarkSword
 *
 * Writes all jailbreak logs to a file on the device.
 * Location:  <AppDocuments>/darksword_log.txt
 * Fallback:  /var/mobile/Documents/darksword_log.txt (after unsandbox)
 *
 * Since there's no SSH access initially, this is the only way
 * to diagnose issues on the device.
 *
 * Access the log via:
 *   - GBox → App → Files section
 *   - Files.app (if UIFileSharingEnabled)
 *   - Filza/SSH after jailbreak succeeds
 */

#ifndef FILELOG_H
#define FILELOG_H

/* Initialize file logger. Call once at the start of exploit_init().
 * Opens the log file and writes device info header. */
void filelog_init(void);

/* Write a log line (printf-style). Appends newline + flushes. */
void filelog_write(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Copy log to well-known locations (call after unsandbox + root).
 * Copies to /var/mobile/Documents/darksword_log.txt */
void filelog_copy_to_shared(void);

/* Flush and close the log file. */
void filelog_close(void);

/* Get the path to the log file (for display to user). */
const char *filelog_get_path(void);

#endif
