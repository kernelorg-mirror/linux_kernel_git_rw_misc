/* SPDX-License-Identifier: GPL-2.0 */
        .section .init.rodata, "a"
        .global embedded_umh_start
embedded_umh_start:
        .incbin "drivers/misc/embedded_prog/eprog_user"
        .global embedded_umh_end
embedded_umh_end:
