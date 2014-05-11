/*
 * Copyright (C) 2004-2006 Atmel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef __ASM_AVR32_TLB_H
#define __ASM_AVR32_TLB_H

#define tlb_start_vma(tlb, vma) \
	flush_cache_range(vma, vma->vm_start, vma->vm_end)

#define tlb_end_vma(tlb, vma) \
	flush_tlb_range(vma, vma->vm_start, vma->vm_end)

#include <asm-generic/tlb.h>

/*
 * For debugging purposes
 */
extern void show_dtlb_entry(unsigned int index);
extern void dump_dtlb(void);

#endif /* __ASM_AVR32_TLB_H */
