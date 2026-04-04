/*
 * darksword_ppl.m — PPL Bypass Stub for Dopamine Plugin System
 *
 * DarkSword's kernel exploit (CVE-2025-43520) achieves physical memory
 * read/write via VFS race + IOSurface contiguous mapping. Physical R/W
 * inherently bypasses PPL (Page Protection Layer) at the hardware level,
 * since PPL only protects virtual memory page tables — it cannot prevent
 * modifications through physical address space access.
 *
 * This stub satisfies Dopamine's requirement for a separate PPL bypass
 * exploit framework. The actual PPL bypass is performed by the kernel
 * exploit's physical memory primitives.
 *
 * Dopamine calls exploit_init/exploit_deinit via dlsym() after loading
 * the framework. We return 0 (success) since PPL is already bypassed.
 */

#import <Foundation/Foundation.h>

#pragma mark - Dopamine PPL Exploit Plugin API

__attribute__((visibility("default")))
int exploit_init(const char *flavor) {
    @autoreleasepool {
        NSLog(@"[darksword_ppl] ========================================");
        NSLog(@"[darksword_ppl] PPL Bypass — via DarkSword physical R/W");
        NSLog(@"[darksword_ppl] Flavor: %s", flavor ?: "default");
        NSLog(@"[darksword_ppl] ========================================");
        NSLog(@"[darksword_ppl] PPL is bypassed by kernel exploit's");
        NSLog(@"[darksword_ppl] physical memory access (IOSurface DMA).");
        NSLog(@"[darksword_ppl] No separate PPL bypass needed.");
        NSLog(@"[darksword_ppl] exploit_init OK");
        return 0;
    }
}

__attribute__((visibility("default")))
void exploit_deinit(void) {
    NSLog(@"[darksword_ppl] exploit_deinit — nothing to clean up");
}
