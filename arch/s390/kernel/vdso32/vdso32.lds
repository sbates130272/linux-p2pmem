/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 * Automatically generated file; DO NOT EDIT.
 * Linux/s390 5.4.0-rc2 Kernel Configuration
 *
 */
/*
 * The use of "&&" / "||" is limited in certain expressions.
 * The following enable to calculate "and" / "or" with macro expansion only.
 */
/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean and tristate options.
 */
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
/*
 * IS_BUILTIN(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise. For boolean options, this is equivalent to
 * IS_ENABLED(CONFIG_FOO).
 */
/*
 * IS_MODULE(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'm', 0
 * otherwise.
 */
/*
 * IS_REACHABLE(CONFIG_FOO) evaluates to 1 if the currently compiled
 * code can call a function defined in code compiled based on CONFIG_FOO.
 * This is similar to IS_ENABLED(), but returns false when invoked from
 * built-in code when CONFIG_FOO is set to 'm'.
 */
/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y' or 'm',
 * 0 otherwise.
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This is the infamous ld script for the 32 bits vdso
 * library
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  S390 version
 *    Copyright IBM Corp. 1999, 2000
 *    Author(s): Hartmut Penner (hp@de.ibm.com)
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* const.h: Macros for dealing with constants.  */
/* Some constant macros are used in both assembler and
 * C code.  Therefore we cannot annotate them always with
 * 'UL' and other type specifiers unilaterally.  We
 * use the following macros to deal with this.
 *
 * Similarly, _AT() will cast an expression with a type in C, but
 * leave it unchanged in asm.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  S390 version
 *
 *  Derived from "include/asm-i386/types.h"
 */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * asm-generic/int-ll64.h
 *
 * Integer declarations for architectures which use "long long"
 * for 64-bit types.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * asm-generic/int-ll64.h
 *
 * Integer declarations for architectures which use "long long"
 * for 64-bit types.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * There seems to be no way of detecting this automatically from user
 * space, so 64 bit architectures should override this in their
 * bitsperlong.h. In particular, an architecture that supports
 * both 32 and 64 bit user space must not rely on CONFIG_64BIT
 * to decide it, but rather check a compiler provided macro.
 */
/*
 * FIXME: The check currently breaks x86-64 build, so it's
 * temporarily disabled. Please fix x86-64 and reenable
 */
/* PAGE_SHIFT determines the page size */
/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  S390 version
 *    Copyright IBM Corp. 1999, 2017
 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  S390 version
 *    Copyright IBM Corp. 1999, 2010
 */
/*
 * Machine features detected in early.c
 */
/* Offsets to entry points in kernel/head.S  */
/* Offsets to parameters in kernel/head.S  */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-License-Identifier: GPL-2.0 */
/* Default link addresses for the vDSOs */
OUTPUT_FORMAT("elf32-s390", "elf32-s390", "elf32-s390")
OUTPUT_ARCH(s390:31-bit)
ENTRY(_start)
SECTIONS
{
 . = 0 + SIZEOF_HEADERS;
 .hash : { *(.hash) } :text
 .gnu.hash : { *(.gnu.hash) }
 .dynsym : { *(.dynsym) }
 .dynstr : { *(.dynstr) }
 .gnu.version : { *(.gnu.version) }
 .gnu.version_d : { *(.gnu.version_d) }
 .gnu.version_r : { *(.gnu.version_r) }
 .note : { *(.note.*) } :text :note
 . = ALIGN(16);
 .text : {
  *(.text .stub .text.* .gnu.linkonce.t.*)
 } :text
 PROVIDE(__etext = .);
 PROVIDE(_etext = .);
 PROVIDE(etext = .);
 /*
	 * Other stuff is appended to the text segment:
	 */
 .rodata : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
 .rodata1 : { *(.rodata1) }
 .dynamic : { *(.dynamic) } :text :dynamic
 .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
 .eh_frame : { KEEP (*(.eh_frame)) } :text
 .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) }
 .rela.dyn ALIGN(8) : { *(.rela.dyn) }
 .got ALIGN(8) : { *(.got .toc) }
 _end = .;
 PROVIDE(end = .);
 /*
	 * Stabs debugging sections are here too.
	 */
 .stab 0 : { *(.stab) }
 .stabstr 0 : { *(.stabstr) }
 .stab.excl 0 : { *(.stab.excl) }
 .stab.exclstr 0 : { *(.stab.exclstr) }
 .stab.index 0 : { *(.stab.index) }
 .stab.indexstr 0 : { *(.stab.indexstr) }
 .comment 0 : { *(.comment) }
 /*
	 * DWARF debug sections.
	 * Symbols in the DWARF debugging sections are relative to the
	 * beginning of the section so we begin them at 0.
	 */
 /* DWARF 1 */
 .debug 0 : { *(.debug) }
 .line 0 : { *(.line) }
 /* GNU DWARF 1 extensions */
 .debug_srcinfo 0 : { *(.debug_srcinfo) }
 .debug_sfnames 0 : { *(.debug_sfnames) }
 /* DWARF 1.1 and DWARF 2 */
 .debug_aranges 0 : { *(.debug_aranges) }
 .debug_pubnames 0 : { *(.debug_pubnames) }
 /* DWARF 2 */
 .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) }
 .debug_abbrev 0 : { *(.debug_abbrev) }
 .debug_line 0 : { *(.debug_line) }
 .debug_frame 0 : { *(.debug_frame) }
 .debug_str 0 : { *(.debug_str) }
 .debug_loc 0 : { *(.debug_loc) }
 .debug_macinfo 0 : { *(.debug_macinfo) }
 /* SGI/MIPS DWARF 2 extensions */
 .debug_weaknames 0 : { *(.debug_weaknames) }
 .debug_funcnames 0 : { *(.debug_funcnames) }
 .debug_typenames 0 : { *(.debug_typenames) }
 .debug_varnames 0 : { *(.debug_varnames) }
 /* DWARF 3 */
 .debug_pubtypes 0 : { *(.debug_pubtypes) }
 .debug_ranges 0 : { *(.debug_ranges) }
 .gnu.attributes 0 : { KEEP (*(.gnu.attributes)) }
 . = ALIGN((1 << 12));
 PROVIDE(_vdso_data = .);
 /DISCARD/ : {
  *(.note.GNU-stack)
  *(.branch_lt)
  *(.data .data.* .gnu.linkonce.d.* .sdata*)
  *(.bss .sbss .dynbss .dynsbss)
 }
}
/*
 * Very old versions of ld do not recognize this name token; use the constant.
 */
/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
 text PT_LOAD FILEHDR PHDRS FLAGS(5); /* PF_R|PF_X */
 dynamic PT_DYNAMIC FLAGS(4); /* PF_R */
 note PT_NOTE FLAGS(4); /* PF_R */
 eh_frame_hdr 0x6474e550;
}
/*
 * This controls what symbols we export from the DSO.
 */
VERSION
{
 LINUX_2.6.29 {
 global:
  /*
		 * Has to be there for the kernel to find
		 */
  __kernel_gettimeofday;
  __kernel_clock_gettime;
  __kernel_clock_getres;
  __kernel_getcpu;
 local: *;
 };
}
