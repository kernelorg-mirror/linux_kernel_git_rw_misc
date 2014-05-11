#ifndef __ASM_TLB_H
#define __ASM_TLB_H

/*
 * MIPS doesn't need any special per-pte or per-vma handling, except
 * we need to flush cache for area to be unmapped.
 */
#define tlb_start_vma(tlb, vma)					\
	do {							\
		if (!tlb->fullmm)				\
			flush_cache_range(vma, vma->vm_start, vma->vm_end); \
	}  while (0)

#define UNIQUE_ENTRYHI(idx)						\
		((CKSEG0 + ((idx) << (PAGE_SHIFT + 1))) |		\
		 (cpu_has_tlbinv ? MIPS_ENTRYHI_EHINV : 0))

#include <asm-generic/tlb.h>

#endif /* __ASM_TLB_H */
