#ifndef TARGET_H
#define TARGET_H

#include "machine.h"

extern struct symbol *size_t_ctype;
extern struct symbol *ssize_t_ctype;
extern struct symbol *ptrdiff_ctype;
extern struct symbol *intptr_ctype;
extern struct symbol *uintptr_ctype;
extern struct symbol *intmax_ctype;
extern struct symbol *uintmax_ctype;
extern struct symbol *int64_ctype;
extern struct symbol *uint64_ctype;
extern struct symbol *int32_ctype;
extern struct symbol *uint32_ctype;
extern struct symbol *wchar_ctype;
extern struct symbol *wint_ctype;
extern struct symbol *least8_ctype;
extern struct symbol *uleast8_ctype;
extern struct symbol *least16_ctype;
extern struct symbol *uleast16_ctype;
extern struct symbol *least32_ctype;
extern struct symbol *uleast32_ctype;
extern struct symbol *least64_ctype;
extern struct symbol *uleast64_ctype;
extern struct symbol *fast8_ctype;
extern struct symbol *ufast8_ctype;
extern struct symbol *fast16_ctype;
extern struct symbol *ufast16_ctype;
extern struct symbol *fast32_ctype;
extern struct symbol *ufast32_ctype;
extern struct symbol *fast64_ctype;
extern struct symbol *ufast64_ctype;
extern struct symbol *sig_atomic_ctype;

/*
 * For "__attribute__((aligned))"
 */
extern int max_alignment;

/*
 * Integer data types
 */
extern int bits_in_bool;
extern int bits_in_char;
extern int bits_in_short;
extern int bits_in_int;
extern int bits_in_long;
extern int bits_in_longlong;
extern int bits_in_longlonglong;

extern int max_int_alignment;

/*
 * Floating point data types
 */
extern int bits_in_float;
extern int bits_in_double;
extern int bits_in_longdouble;

extern int max_fp_alignment;

/*
 * Pointer data type
 */
extern int bits_in_pointer;
extern int pointer_alignment;

/*
 * Enum data types
 */
extern int bits_in_enum;
extern int enum_alignment;

struct asm_operand;
struct builtin_fn;

struct target {
	enum machine	mach;
	enum bitness	bitness;
	unsigned int	big_endian:1;
	unsigned int	unsigned_char:1;
	unsigned int	size_t_long:1;
	unsigned int	has_int128:1;
	unsigned long	flags;

	struct symbol	*wchar;
	struct symbol	*wint;

	unsigned int	bits_in_longdouble;
	unsigned int	max_fp_alignment;

	const struct target *target_32bit;
	const struct target *target_x32bit;
	const struct target *target_64bit;

	const struct builtin_fn *builtins;

	void (*init)(const struct target *self);
	void (*parse_march)(const char *arg);
	void (*predefine)(const struct target *self);
	const char *(*asm_constraint)(struct asm_operand *op, int c, const char *str);
};

extern const struct target target_default;
extern const struct target target_alpha;
extern const struct target target_arm;
extern const struct target target_arm64;
extern const struct target target_bfin;
extern const struct target target_h8300;
extern const struct target target_m68k;
extern const struct target target_microblaze;
extern const struct target target_mips32;
extern const struct target target_mips64;
extern const struct target target_nds32;
extern const struct target target_nios2;
extern const struct target target_openrisc;
extern const struct target target_ppc32;
extern const struct target target_ppc64;
extern const struct target target_riscv32;
extern const struct target target_riscv64;
extern const struct target target_s390;
extern const struct target target_s390x;
extern const struct target target_sh;
extern const struct target target_sparc32;
extern const struct target target_sparc64;
extern const struct target target_i386;
extern const struct target target_x86_64;
extern const struct target target_xtensa;

/* target.c */
extern const struct target *arch_target;

enum machine target_parse(const char *name);
void target_os(const char *name);
void target_config(enum machine mach);
void target_init(void);

/*
 * Helper functions for converting bits to bytes and vice versa.
 */

static inline int bits_to_bytes(int bits)
{
	return bits >= 0 ? (bits + bits_in_char - 1) / bits_in_char : -1;
}

static inline int bytes_to_bits(int bytes)
{
	return bytes * bits_in_char;
}

static inline unsigned long array_element_offset(unsigned long base_bits, int idx)
{
	int fragment = base_bits % bits_in_char;
	if (fragment)
		base_bits += bits_in_char - fragment;
	return base_bits * idx;
}

#endif
