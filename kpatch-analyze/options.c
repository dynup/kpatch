// SPDX-License-Identifier: MIT
/*
 * 'sparse' library helper routines.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 *               2017-2020 Luc Van Oostenryck
 */

#include "options.h"
#include "lib.h"
#include "machine.h"
#include "target.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifndef __GNUC__
# define __GNUC__ 2
# define __GNUC_MINOR__ 95
# define __GNUC_PATCHLEVEL__ 0
#endif

enum flag_type {
	FLAG_OFF,
	FLAG_ON,
	FLAG_FORCE_OFF
};

int die_if_error = 0;
int do_output = 1;
int gcc_major = __GNUC__;
int gcc_minor = __GNUC_MINOR__;
int gcc_patchlevel = __GNUC_PATCHLEVEL__;
int has_error = 0;
int optimize_level;
int optimize_size;
int preprocess_only;
int preprocessing;
int verbose;

#define CMDLINE_INCLUDE 20
int cmdline_include_nr = 0;
char *cmdline_include[CMDLINE_INCLUDE];

const char *base_filename;
const char *diag_prefix = "";
const char *gcc_base_dir = GCC_BASE;
const char *multiarch_dir = MULTIARCH_TRIPLET;
const char *outfile = NULL;

enum standard standard = STANDARD_GNU89;

int arch_big_endian = ARCH_BIG_ENDIAN;
int arch_cmodel = CMODEL_UNKNOWN;
int arch_fp_abi = FP_ABI_NATIVE;
int arch_m64 = ARCH_M64_DEFAULT;
int arch_msize_long = 0;
int arch_os = OS_NATIVE;

int dbg_compound = 0;
int dbg_dead = 0;
int dbg_domtree = 0;
int dbg_entry = 0;
int dbg_ir = 0;
int dbg_postorder = 0;

int dump_macro_defs = 0;
int dump_macros_only = 0;

unsigned long fdump_ir;
int fhosted = 1;
unsigned int fmax_errors = 100;
unsigned int fmax_warnings = 100;
int fmem_report = 0;
unsigned long long fmemcpy_max_count = 100000;
unsigned long fpasses = ~0UL;
int fpic = 0;
int fpie = 0;
int fshort_wchar = 0;
int funsigned_bitfields = 0;
int funsigned_char = 0;

int Waddress = 0;
int Waddress_space = 1;
int Wbitwise = 1;
int Wbitwise_pointer = 0;
int Wcast_from_as = 0;
int Wcast_to_as = 0;
int Wcast_truncate = 1;
int Wconstant_suffix = 0;
int Wconstexpr_not_const = 0;
int Wcontext = 1;
int Wdecl = 1;
int Wdeclarationafterstatement = -1;
int Wdefault_bitfield_sign = 0;
int Wdesignated_init = 1;
int Wdo_while = 0;
int Wenum_mismatch = 1;
int Wexternal_function_has_definition = 1;
int Wflexible_array_array = 1;
int Wflexible_array_nested = 0;
int Wflexible_array_sizeof = 0;
int Wflexible_array_union = 0;
int Wimplicit_int = 1;
int Winit_cstring = 0;
int Wint_to_pointer_cast = 1;
int Wmemcpy_max_count = 1;
int Wnewline_eof = 1;
int Wnon_pointer_null = 1;
int Wold_initializer = 1;
int Wold_style_definition = 1;
int Wone_bit_signed_bitfield = 1;
int Woverride_init = 1;
int Woverride_init_all = 0;
int Woverride_init_whole_range = 0;
int Wparen_string = 0;
int Wpast_deep_designator = 0;
int Wpedantic = 0;
int Wpointer_arith = 0;
int Wpointer_to_int_cast = 1;
int Wptr_subtraction_blows = 0;
int Wreturn_void = 0;
int Wshadow = 0;
int Wshift_count_negative = 1;
int Wshift_count_overflow = 1;
int Wsizeof_bool = 0;
int Wsparse_error = FLAG_FORCE_OFF;
int Wstrict_prototypes = 1;
int Wtautological_compare = 0;
int Wtransparent_union = 0;
int Wtypesign = 0;
int Wundef = 0;
int Wuninitialized = 1;
int Wunion_cast = 0;
int Wuniversal_initializer = 0;
int Wunknown_attribute = 0;
int Wvla = 1;

////////////////////////////////////////////////////////////////////////////////
// Helpers for option parsing

static const char *match_option(const char *arg, const char *prefix)
{
	unsigned int n = strlen(prefix);
	if (strncmp(arg, prefix, n) == 0)
		return arg + n;
	return NULL;
}


struct val_map {
	const char *name;
	int val;
};

static int handle_subopt_val(const char *opt, const char *arg, const struct val_map *map, int *flag)
{
	const char *name;

	if (*arg++ != '=')
		die("missing argument for option '%s'", opt);
	for (;(name = map->name); map++) {
		if (strcmp(name, arg) == 0 || strcmp(name, "*") == 0) {
			*flag = map->val;
			return 1;
		}
		if (strcmp(name, "?") == 0)
			die("invalid argument '%s' in option '%s'", arg, opt);
	}
	return 0;
}


struct mask_map {
	const char *name;
	unsigned long mask;
};

static int apply_mask(unsigned long *val, const char *str, unsigned len, const struct mask_map *map, int neg)
{
	const char *name;

	for (;(name = map->name); map++) {
		if (!strncmp(name, str, len) && !name[len]) {
			if (neg == 0)
				*val |= map->mask;
			else
				*val &= ~map->mask;
			return 0;
		}
	}
	return 1;
}

static int handle_suboption_mask(const char *arg, const char *opt, const struct mask_map *map, unsigned long *flag)
{
	if (*opt == '\0') {
		apply_mask(flag, "", 0, map, 0);
		return 1;
	}
	if (*opt++ != '=')
		return 0;
	while (1) {
		unsigned int len = strcspn(opt, ",+");
		int neg = 0;
		if (len == 0)
			goto end;
		if (!strncmp(opt, "no-", 3)) {
			opt += 3;
			len -= 3;
			neg = 1;
		}
		if (apply_mask(flag, opt, len, map, neg))
			die("error: wrong option '%.*s' for \'%s\'", len, opt, arg);

end:
		opt += len;
		if (*opt++ == '\0')
			break;
	}
	return 1;
}


#define OPT_INVERSE	1
#define OPT_VAL		2
struct flag {
	const char *name;
	int *flag;
	int (*fun)(const char *arg, const char *opt, const struct flag *, int options);
	unsigned long mask;
	int val;
};

static int handle_switches(const char *ori, const char *opt, const struct flag *flags)
{
	const char *arg = opt;
	int val = 1;

	// Prefixe "no-" mean to turn flag off.
	if (strncmp(arg, "no-", 3) == 0) {
		arg += 3;
		val = 0;
	}

	for (; flags->name; flags++) {
		const char *opt = match_option(arg, flags->name);
		int rc;

		if (!opt)
			continue;

		if (flags->fun) {
			int options = 0;
			if (!val)
				options |= OPT_INVERSE;
			if ((rc = flags->fun(ori, opt, flags, options)))
				return rc;
		}

		// boolean flag
		if (opt[0] == '\0' && flags->flag) {
			if (flags->mask & OPT_VAL)
				val = flags->val;
			if (flags->mask & OPT_INVERSE)
				val = !val;
			*flags->flag = val;
			return 1;
		}
	}

	// not handled
	return 0;
}

static char **handle_onoff_switch(char *arg, char **next, const struct flag flags[])
{
	int flag = FLAG_ON;
	char *p = arg + 1;
	unsigned i;

	// Prefixes "no" and "no-" mean to turn warning off.
	if (p[0] == 'n' && p[1] == 'o') {
		p += 2;
		if (p[0] == '-')
			p++;
		flag = FLAG_FORCE_OFF;
	}

	for (i = 0; flags[i].name; i++) {
		if (!strcmp(p,flags[i].name)) {
			*flags[i].flag = flag;
			return next;
		}
	}

	// Unknown.
	return NULL;
}

static void handle_onoff_switch_finalize(const struct flag flags[])
{
	unsigned i;

	for (i = 0; flags[i].name; i++) {
		if (*flags[i].flag == FLAG_FORCE_OFF)
			*flags[i].flag = FLAG_OFF;
	}
}

static int handle_switch_setval(const char *arg, const char *opt, const struct flag *flag, int options)
{
	*(flag->flag) = flag->mask;
	return 1;
}


#define	OPTNUM_ZERO_IS_INF		1
#define	OPTNUM_UNLIMITED		2

#define OPT_NUMERIC(NAME, TYPE, FUNCTION)	\
static int opt_##NAME(const char *arg, const char *opt, TYPE *ptr, int flag)	\
{									\
	char *end;							\
	TYPE val;							\
									\
	val = FUNCTION(opt, &end, 0);					\
	if (*end != '\0' || end == opt) {				\
		if ((flag & OPTNUM_UNLIMITED) && !strcmp(opt, "unlimited"))	\
			val = ~val;					\
		else							\
			die("error: wrong argument to \'%s\'", arg);	\
	}								\
	if ((flag & OPTNUM_ZERO_IS_INF) && val == 0)			\
		val = ~val;						\
	*ptr = val;							\
	return 1;							\
}

OPT_NUMERIC(ullong, unsigned long long, strtoull)
OPT_NUMERIC(uint, unsigned int, strtoul)

////////////////////////////////////////////////////////////////////////////////
// Option parsing

static char **handle_switch_a(char *arg, char **next)
{
	if (!strcmp(arg, "ansi"))
		standard = STANDARD_C89;

	return next;
}

static char **handle_switch_D(char *arg, char **next)
{
	const char *name = arg + 1;
	const char *value = "1";

	if (!*name) {
		arg = *++next;
		if (!arg)
			die("argument to `-D' is missing");
		name = arg;
	}

	for (;;arg++) {
		char c;
		c = *arg;
		if (!c)
			break;
		if (c == '=') {
			*arg = '\0';
			value = arg + 1;
			break;
		}
	}
	add_pre_buffer("#define %s %s\n", name, value);
	return next;
}

static char **handle_switch_d(char *arg, char **next)
{
	char *arg_char = arg + 1;

	/*
	 * -d<CHARS>, where <CHARS> is a sequence of characters, not preceded
	 * by a space. If you specify characters whose behaviour conflicts,
	 * the result is undefined.
	 */
	while (*arg_char) {
		switch (*arg_char) {
		case 'M': /* dump just the macro definitions */
			dump_macros_only = 1;
			dump_macro_defs = 0;
			break;
		case 'D': /* like 'M', but also output pre-processed text */
			dump_macro_defs = 1;
			dump_macros_only = 0;
			break;
		case 'N': /* like 'D', but only output macro names not bodies */
			break;
		case 'I': /* like 'D', but also output #include directives */
			break;
		case 'U': /* like 'D', but only output expanded macros */
			break;
		}
		arg_char++;
	}
	return next;
}

static char **handle_switch_E(char *arg, char **next)
{
	if (arg[1] == '\0')
		preprocess_only = 1;
	return next;
}

static int handle_ftabstop(const char *arg, const char *opt, const struct flag *flag, int options)
{
	unsigned long val;
	char *end;

	if (*opt == '\0')
		die("error: missing argument to \"%s\"", arg);

	/* we silently ignore silly values */
	val = strtoul(opt, &end, 10);
	if (*end == '\0' && 1 <= val && val <= 100)
		tabstop = val;

	return 1;
}

static int handle_fpasses(const char *arg, const char *opt, const struct flag *flag, int options)
{
	unsigned long mask;

	mask = flag->mask;
	if (*opt == '\0') {
		if (options & OPT_INVERSE)
			fpasses &= ~mask;
		else
			fpasses |=  mask;
		return 1;
	}
	if (options & OPT_INVERSE)
		return 0;
	if (!strcmp(opt, "-enable")) {
		fpasses |= mask;
		return 1;
	}
	if (!strcmp(opt, "-disable")) {
		fpasses &= ~mask;
		return 1;
	}
	if (!strcmp(opt, "=last")) {
		// clear everything above
		mask |= mask - 1;
		fpasses &= mask;
		return 1;
	}
	return 0;
}

static int handle_fdiagnostic_prefix(const char *arg, const char *opt, const struct flag *flag, int options)
{
	switch (*opt) {
	case '\0':
		diag_prefix = "sparse: ";
		return 1;
	case '=':
		diag_prefix = xasprintf("%s: ", opt+1);
		return 1;
	default:
		return 0;
	}
}

static int handle_fdump_ir(const char *arg, const char *opt, const struct flag *flag, int options)
{
	static const struct mask_map dump_ir_options[] = {
		{ "",			PASS_LINEARIZE },
		{ "linearize",		PASS_LINEARIZE },
		{ "mem2reg",		PASS_MEM2REG },
		{ "final",		PASS_FINAL },
		{ },
	};

	return handle_suboption_mask(arg, opt, dump_ir_options, &fdump_ir);
}

static int handle_fmemcpy_max_count(const char *arg, const char *opt, const struct flag *flag, int options)
{
	opt_ullong(arg, opt, &fmemcpy_max_count, OPTNUM_ZERO_IS_INF|OPTNUM_UNLIMITED);
	return 1;
}

static int handle_fmax_errors(const char *arg, const char *opt, const struct flag *flag, int options)
{
	opt_uint(arg, opt, &fmax_errors, OPTNUM_UNLIMITED);
	return 1;
}

static int handle_fmax_warnings(const char *arg, const char *opt, const struct flag *flag, int options)
{
	opt_uint(arg, opt, &fmax_warnings, OPTNUM_UNLIMITED);
	return 1;
}

static struct flag fflags[] = {
	{ "diagnostic-prefix",	NULL,	handle_fdiagnostic_prefix },
	{ "dump-ir",		NULL,	handle_fdump_ir },
	{ "freestanding",	&fhosted, NULL, OPT_INVERSE },
	{ "hosted",		&fhosted },
	{ "linearize",		NULL,	handle_fpasses,	PASS_LINEARIZE },
	{ "max-errors=",	NULL,	handle_fmax_errors },
	{ "max-warnings=",	NULL,	handle_fmax_warnings },
	{ "mem-report",		&fmem_report },
	{ "memcpy-max-count=",	NULL,	handle_fmemcpy_max_count },
	{ "tabstop=",		NULL,	handle_ftabstop },
	{ "mem2reg",		NULL,	handle_fpasses,	PASS_MEM2REG },
	{ "optim",		NULL,	handle_fpasses,	PASS_OPTIM },
	{ "pic",		&fpic,	handle_switch_setval, 1 },
	{ "PIC",		&fpic,	handle_switch_setval, 2 },
	{ "pie",		&fpie,	handle_switch_setval, 1 },
	{ "PIE",		&fpie,	handle_switch_setval, 2 },
	{ "signed-bitfields",	&funsigned_bitfields, NULL, OPT_INVERSE },
	{ "unsigned-bitfields",	&funsigned_bitfields, NULL, },
	{ "signed-char",	&funsigned_char, NULL,	OPT_INVERSE },
	{ "short-wchar",	&fshort_wchar },
	{ "unsigned-char",	&funsigned_char, NULL, },
	{ },
};

static char **handle_switch_f(char *arg, char **next)
{
	if (handle_switches(arg-1, arg+1, fflags))
		return next;

	return next;
}

static char **handle_switch_G(char *arg, char **next)
{
	if (!strcmp(arg, "G") && *next)
		return next + 1; // "-G 0"
	else
		return next;     // "-G0" or (bogus) terminal "-G"
}

static char **handle_base_dir(char *arg, char **next)
{
	gcc_base_dir = *++next;
	if (!gcc_base_dir)
		die("missing argument for -gcc-base-dir option");
	return next;
}

static char **handle_switch_g(char *arg, char **next)
{
	if (!strcmp(arg, "gcc-base-dir"))
		return handle_base_dir(arg, next);

	return next;
}

static char **handle_switch_I(char *arg, char **next)
{
	char *path = arg+1;

	switch (arg[1]) {
	case '-':
		add_pre_buffer("#split_include\n");
		break;

	case '\0':	/* Plain "-I" */
		path = *++next;
		if (!path)
			die("missing argument for -I option");
		/* Fall through */
	default:
		add_pre_buffer("#add_include \"%s/\"\n", path);
	}
	return next;
}

static void add_cmdline_include(char *filename)
{
	if (cmdline_include_nr >= CMDLINE_INCLUDE)
		die("too many include files for %s\n", filename);
	cmdline_include[cmdline_include_nr++] = filename;
}

static char **handle_switch_i(char *arg, char **next)
{
	if (*next && !strcmp(arg, "include"))
		add_cmdline_include(*++next);
	else if (*next && !strcmp(arg, "imacros"))
		add_cmdline_include(*++next);
	else if (*next && !strcmp(arg, "isystem")) {
		char *path = *++next;
		if (!path)
			die("missing argument for -isystem option");
		add_pre_buffer("#add_isystem \"%s/\"\n", path);
	} else if (*next && !strcmp(arg, "idirafter")) {
		char *path = *++next;
		if (!path)
			die("missing argument for -idirafter option");
		add_pre_buffer("#add_dirafter \"%s/\"\n", path);
	}
	return next;
}

static char **handle_switch_M(char *arg, char **next)
{
	if (!strcmp(arg, "MF") || !strcmp(arg,"MQ") || !strcmp(arg,"MT")) {
		if (!*next)
			die("missing argument for -%s option", arg);
		return next + 1;
	}
	return next;
}

static int handle_march(const char *opt, const char *arg, const struct flag *flag, int options)
{
	if (arch_target->parse_march)
		arch_target->parse_march(arg);
	return 1;
}

static int handle_mcmodel(const char *opt, const char *arg, const struct flag *flag, int options)
{
	static const struct val_map cmodels[] = {
		{ "kernel",	CMODEL_KERNEL },
		{ "large",	CMODEL_LARGE },
		{ "medany",	CMODEL_MEDANY },
		{ "medium",	CMODEL_MEDIUM },
		{ "medlow",	CMODEL_MEDLOW },
		{ "small",	CMODEL_SMALL },
		{ "tiny",	CMODEL_TINY },
		{ },
	};
	return handle_subopt_val(opt, arg, cmodels, flag->flag);
}

static int handle_mfloat_abi(const char *opt, const char *arg, const struct flag *flag, int options) {
	static const struct val_map fp_abis[] = {
		{ "hard",		FP_ABI_HARD },
		{ "soft",		FP_ABI_SOFT },
		{ "softfp",		FP_ABI_HYBRID },
		{ "?" },
	};
	return handle_subopt_val(opt, arg, fp_abis, flag->flag);
}

static char **handle_multiarch_dir(char *arg, char **next)
{
	multiarch_dir = *++next;
	if (!multiarch_dir)
		die("missing argument for -multiarch-dir option");
	return next;
}

static const struct flag mflags[] = {
	{ "64", &arch_m64, NULL, OPT_VAL, ARCH_LP64 },
	{ "32", &arch_m64, NULL, OPT_VAL, ARCH_LP32 },
	{ "31", &arch_m64, NULL, OPT_VAL, ARCH_LP32 },
	{ "16", &arch_m64, NULL, OPT_VAL, ARCH_LP32 },
	{ "x32",&arch_m64, NULL, OPT_VAL, ARCH_X32 },
	{ "size-llp64", &arch_m64, NULL, OPT_VAL, ARCH_LLP64 },
	{ "size-long", &arch_msize_long },
	{ "arch=", NULL, handle_march },
	{ "big-endian", &arch_big_endian, NULL },
	{ "little-endian", &arch_big_endian, NULL, OPT_INVERSE },
	{ "cmodel", &arch_cmodel, handle_mcmodel },
	{ "float-abi", &arch_fp_abi, handle_mfloat_abi },
	{ "hard-float", &arch_fp_abi, NULL, OPT_VAL, FP_ABI_HARD },
	{ "soft-float", &arch_fp_abi, NULL, OPT_VAL, FP_ABI_SOFT },
	{ }
};

static char **handle_switch_m(char *arg, char **next)
{
	if (!strcmp(arg, "multiarch-dir")) {
		return handle_multiarch_dir(arg, next);
	} else {
		handle_switches(arg-1, arg+1, mflags);
	}

	return next;
}

static char **handle_nostdinc(char *arg, char **next)
{
	add_pre_buffer("#nostdinc\n");
	return next;
}

static char **handle_switch_n(char *arg, char **next)
{
	if (!strcmp(arg, "nostdinc"))
		return handle_nostdinc(arg, next);

	return next;
}

static char **handle_switch_O(char *arg, char **next)
{
	int level = 1;
	if (arg[1] >= '0' && arg[1] <= '9')
		level = arg[1] - '0';
	optimize_level = level;
	optimize_size = arg[1] == 's';
	return next;
}

static char **handle_switch_o(char *arg, char **next)
{
	if (!strcmp(arg, "o")) {	// "-o foo"
		if (!*++next)
			die("argument to '-o' is missing");
		outfile = *next;
	}
	// else "-ofoo"

	return next;
}

static const struct flag pflags[] = {
	{ "pedantic", &Wpedantic, NULL, OPT_VAL, FLAG_ON },
	{ }
};

static char **handle_switch_p(char *arg, char **next)
{
	handle_switches(arg-1, arg, pflags);
	return next;
}

static char **handle_switch_s(const char *arg, char **next)
{
	if ((arg = match_option(arg, "std="))) {
		if (!strcmp(arg, "c89") ||
		    !strcmp(arg, "iso9899:1990"))
			standard = STANDARD_C89;

		else if (!strcmp(arg, "iso9899:199409"))
			standard = STANDARD_C94;

		else if (!strcmp(arg, "c99") ||
			 !strcmp(arg, "c9x") ||
			 !strcmp(arg, "iso9899:1999") ||
			 !strcmp(arg, "iso9899:199x"))
			standard = STANDARD_C99;

		else if (!strcmp(arg, "gnu89"))
			standard = STANDARD_GNU89;

		else if (!strcmp(arg, "gnu99") || !strcmp(arg, "gnu9x"))
			standard = STANDARD_GNU99;

		else if (!strcmp(arg, "c11") ||
			 !strcmp(arg, "c1x") ||
			 !strcmp(arg, "iso9899:2011"))
			standard = STANDARD_C11;

		else if (!strcmp(arg, "gnu11"))
			standard = STANDARD_GNU11;

		else if (!strcmp(arg, "c17") ||
			 !strcmp(arg, "c18") ||
			 !strcmp(arg, "iso9899:2017") ||
			 !strcmp(arg, "iso9899:2018"))
			standard = STANDARD_C17;
		else if (!strcmp(arg, "gnu17") ||
			 !strcmp(arg, "gnu18"))
			standard = STANDARD_GNU17;

		else
			die("Unsupported C dialect");
	}

	return next;
}

static char **handle_switch_U(char *arg, char **next)
{
	const char *name = arg + 1;

	if (*name == '\0') {
		name = *++next;
		if (!name)
			die("argument to `-U' is missing");
	}
	add_pre_buffer("#undef %s\n", name);
	return next;
}

static struct flag debugs[] = {
	{ "compound", &dbg_compound},
	{ "dead", &dbg_dead},
	{ "domtree", &dbg_domtree},
	{ "entry", &dbg_entry},
	{ "ir", &dbg_ir},
	{ "postorder", &dbg_postorder},
	{ }
};

static char **handle_switch_v(char *arg, char **next)
{
	char ** ret = handle_onoff_switch(arg, next, debugs);
	if (ret)
		return ret;

	// Unknown.
	do {
		verbose++;
	} while (*++arg == 'v');
	return next;
}

static void handle_switch_v_finalize(void)
{
	handle_onoff_switch_finalize(debugs);
}

static const struct flag warnings[] = {
	{ "address", &Waddress },
	{ "address-space", &Waddress_space },
	{ "bitwise", &Wbitwise },
	{ "bitwise-pointer", &Wbitwise_pointer},
	{ "cast-from-as", &Wcast_from_as },
	{ "cast-to-as", &Wcast_to_as },
	{ "cast-truncate", &Wcast_truncate },
	{ "constant-suffix", &Wconstant_suffix },
	{ "constexpr-not-const", &Wconstexpr_not_const},
	{ "context", &Wcontext },
	{ "decl", &Wdecl },
	{ "declaration-after-statement", &Wdeclarationafterstatement },
	{ "default-bitfield-sign", &Wdefault_bitfield_sign },
	{ "designated-init", &Wdesignated_init },
	{ "do-while", &Wdo_while },
	{ "enum-mismatch", &Wenum_mismatch },
	{ "external-function-has-definition", &Wexternal_function_has_definition },
	{ "flexible-array-array", &Wflexible_array_array },
	{ "flexible-array-nested", &Wflexible_array_nested },
	{ "flexible-array-sizeof", &Wflexible_array_sizeof },
	{ "flexible-array-union", &Wflexible_array_union },
	{ "implicit-int", &Wimplicit_int },
	{ "init-cstring", &Winit_cstring },
	{ "int-to-pointer-cast", &Wint_to_pointer_cast },
	{ "memcpy-max-count", &Wmemcpy_max_count },
	{ "non-pointer-null", &Wnon_pointer_null },
	{ "newline-eof", &Wnewline_eof },
	{ "old-initializer", &Wold_initializer },
	{ "old-style-definition", &Wold_style_definition },
	{ "one-bit-signed-bitfield", &Wone_bit_signed_bitfield },
	{ "override-init", &Woverride_init },
	{ "override-init-all", &Woverride_init_all },
	{ "paren-string", &Wparen_string },
	{ "past-deep-designator", &Wpast_deep_designator },
	{ "pedantic", &Wpedantic },
	{ "pointer-to-int-cast", &Wpointer_to_int_cast },
	{ "ptr-subtraction-blows", &Wptr_subtraction_blows },
	{ "return-void", &Wreturn_void },
	{ "shadow", &Wshadow },
	{ "shift-count-negative", &Wshift_count_negative },
	{ "shift-count-overflow", &Wshift_count_overflow },
	{ "sizeof-bool", &Wsizeof_bool },
	{ "strict-prototypes", &Wstrict_prototypes },
	{ "pointer-arith", &Wpointer_arith },
	{ "sparse-error", &Wsparse_error },
	{ "tautological-compare", &Wtautological_compare },
	{ "transparent-union", &Wtransparent_union },
	{ "typesign", &Wtypesign },
	{ "undef", &Wundef },
	{ "uninitialized", &Wuninitialized },
	{ "union-cast", &Wunion_cast },
	{ "universal-initializer", &Wuniversal_initializer },
	{ "unknown-attribute", &Wunknown_attribute },
	{ "vla", &Wvla },
	{ }
};

static char **handle_switch_W(char *arg, char **next)
{
	char ** ret = handle_onoff_switch(arg, next, warnings);
	if (ret)
		return ret;

	if (!strcmp(arg, "Wsparse-all")) {
		int i;
		for (i = 0; warnings[i].name; i++) {
			if (*warnings[i].flag != FLAG_FORCE_OFF)
				*warnings[i].flag = FLAG_ON;
		}
	}

	// Unknown.
	return next;
}

static void handle_switch_W_finalize(void)
{
	handle_onoff_switch_finalize(warnings);

	/* default Wdeclarationafterstatement based on the C dialect */
	if (-1 == Wdeclarationafterstatement) {
		switch (standard) {
			case STANDARD_C89:
			case STANDARD_C94:
				Wdeclarationafterstatement = 1;
				break;
			default:
				Wdeclarationafterstatement = 0;
				break;
		}
	}
}

static char **handle_switch_x(char *arg, char **next)
{
	if (!*++next)
		die("missing argument for -x option");
	return next;
}


static char **handle_arch(char *arg, char **next)
{
	enum machine mach;

	if (*arg++ != '=')
		die("missing argument for --arch option");

	mach = target_parse(arg);
	if (mach != MACH_UNKNOWN)
		target_config(mach);

	return next;
}

static char **handle_param(char *arg, char **next)
{
	char *value = NULL;

	/* For now just skip any '--param=*' or '--param *' */
	if (*arg == '\0') {
		value = *++next;
	} else if (isspace((unsigned char)*arg) || *arg == '=') {
		value = ++arg;
	}

	if (!value)
		die("missing argument for --param option");

	return next;
}

static char **handle_os(char *arg, char **next)
{
	if (*arg++ != '=')
		die("missing argument for --os option");

	target_os(arg);

	return next;
}

static char **handle_version(char *arg, char **next)
{
	printf("%s\n", sparse_version);
	exit(0);
}

struct switches {
	const char *name;
	char **(*fn)(char *, char **);
	unsigned int prefix:1;
};

static char **handle_long_options(char *arg, char **next)
{
	static struct switches cmd[] = {
		{ "arch", handle_arch, 1 },
		{ "os",   handle_os, 1 },
		{ "param", handle_param, 1 },
		{ "version", handle_version },
		{ NULL, NULL }
	};
	struct switches *s = cmd;

	while (s->name) {
		int optlen = strlen(s->name);
		if (!strncmp(s->name, arg, optlen + !s->prefix))
			return s->fn(arg + optlen, next);
		s++;
	}
	return next;
}

char **handle_switch(char *arg, char **next)
{
	switch (*arg) {
	case 'a': return handle_switch_a(arg, next);
	case 'D': return handle_switch_D(arg, next);
	case 'd': return handle_switch_d(arg, next);
	case 'E': return handle_switch_E(arg, next);
	case 'f': return handle_switch_f(arg, next);
	case 'g': return handle_switch_g(arg, next);
	case 'G': return handle_switch_G(arg, next);
	case 'I': return handle_switch_I(arg, next);
	case 'i': return handle_switch_i(arg, next);
	case 'M': return handle_switch_M(arg, next);
	case 'm': return handle_switch_m(arg, next);
	case 'n': return handle_switch_n(arg, next);
	case 'o': return handle_switch_o(arg, next);
	case 'O': return handle_switch_O(arg, next);
	case 'p': return handle_switch_p(arg, next);
	case 's': return handle_switch_s(arg, next);
	case 'U': return handle_switch_U(arg, next);
	case 'v': return handle_switch_v(arg, next);
	case 'W': return handle_switch_W(arg, next);
	case 'x': return handle_switch_x(arg, next);
	case '-': return handle_long_options(arg + 1, next);
	default:
		break;
	}

	/*
	 * Ignore unknown command line options:
	 * they're probably gcc switches
	 */
	return next;
}

void handle_switch_finalize(void)
{
	handle_switch_v_finalize();
	handle_switch_W_finalize();
}
