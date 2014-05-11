#ifndef _ASM_TLB_H
#define _ASM_TLB_H

#include <asm/tlbflush.h>

#ifdef CONFIG_MMU
extern void check_pgt_cache(void);
#else
#define check_pgt_cache() do {} while(0)
#endif

#include <asm-generic/tlb.h>

#endif /* _ASM_TLB_H */

