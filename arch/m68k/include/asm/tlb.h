#ifndef _M68K_TLB_H
#define _M68K_TLB_H

#ifdef CONFIG_MMU && !defined(CONFIG_COLDFIRE) && !defined(CONFIG_SUN3)
/* These defines are needed to override the defaults from asm-generic/tlb.h */
#define __pte_free_tlb __pte_free_tlb
#define __pmd_free_tlb __pmd_free_tlb
#endif

#include <asm-generic/tlb.h>

#endif /* _M68K_TLB_H */
