//
//  utils.h — from rooootdev/lara (25.03.26)
//

#ifndef utils_h
#define utils_h

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dynamic PID offset (0xD8 on iOS 15..17, 0x60 on iOS 18.4+) */
extern uint32_t PROC_PID_OFFSET;

void     init_offsets(void);
uint64_t ourproc(void);
uint64_t ourtask(uint64_t procaddr);
uint64_t procbyname(const char *procname);

#ifdef __cplusplus
}
#endif

#endif /* utils_h */
