#ifndef OPTIONS_H
#define OPTIONS_H

enum {
	CMODEL_UNKNOWN,
	CMODEL_KERNEL,
	CMODEL_LARGE,
	CMODEL_MEDANY,
	CMODEL_MEDIUM,
	CMODEL_MEDLOW,
	CMODEL_PIC,
	CMODEL_SMALL,
	CMODEL_TINY,
	CMODEL_LAST,
};

enum standard {
	STANDARD_NONE,
	STANDARD_GNU,
	STANDARD_C89,
	STANDARD_GNU89 = STANDARD_C89 | STANDARD_GNU,
	STANDARD_C94,
	STANDARD_GNU94 = STANDARD_C94 | STANDARD_GNU,
	STANDARD_C99,
	STANDARD_GNU99 = STANDARD_C99 | STANDARD_GNU,
	STANDARD_C11,
	STANDARD_GNU11 = STANDARD_C11 | STANDARD_GNU,
	STANDARD_C17,
	STANDARD_GNU17 = STANDARD_C17 | STANDARD_GNU,
};

extern int die_if_error;
extern int do_output;
extern int gcc_major;
extern int gcc_minor;
extern int gcc_patchlevel;
extern int optimize_level;
extern int optimize_size;
extern int preprocess_only;
extern int preprocessing;
extern int repeat_phase;
extern int verbose;

extern int cmdline_include_nr;
extern char *cmdline_include[];

extern const char *base_filename;
extern const char *diag_prefix;
extern const char *gcc_base_dir;
extern const char *multiarch_dir;
extern const char *outfile;

extern enum standard standard;
extern unsigned int tabstop;

extern int arch_big_endian;
extern int arch_cmodel;
extern int arch_fp_abi;
extern int arch_m64;
extern int arch_msize_long;
extern int arch_os;

extern int dbg_compound;
extern int dbg_dead;
extern int dbg_domtree;
extern int dbg_entry;
extern int dbg_ir;
extern int dbg_postorder;

extern int dump_macro_defs;
extern int dump_macros_only;

extern unsigned long fdump_ir;
extern int fhosted;
extern unsigned int fmax_errors;
extern unsigned int fmax_warnings;
extern int fmem_report;
extern unsigned long long fmemcpy_max_count;
extern unsigned long fpasses;
extern int fpic;
extern int fpie;
extern int fshort_wchar;
extern int funsigned_bitfields;
extern int funsigned_char;

extern int Waddress;
extern int Waddress_space;
extern int Wbitwise;
extern int Wbitwise_pointer;
extern int Wcast_from_as;
extern int Wcast_to_as;
extern int Wcast_truncate;
extern int Wconstant_suffix;
extern int Wconstexpr_not_const;
extern int Wcontext;
extern int Wdecl;
extern int Wdeclarationafterstatement;
extern int Wdefault_bitfield_sign;
extern int Wdesignated_init;
extern int Wdo_while;
extern int Wenum_mismatch;
extern int Wexternal_function_has_definition;
extern int Wflexible_array_array;
extern int Wflexible_array_nested;
extern int Wflexible_array_sizeof;
extern int Wflexible_array_union;
extern int Wimplicit_int;
extern int Winit_cstring;
extern int Wint_to_pointer_cast;
extern int Wmemcpy_max_count;
extern int Wnewline_eof;
extern int Wnon_pointer_null;
extern int Wold_initializer;
extern int Wold_style_definition;
extern int Wone_bit_signed_bitfield;
extern int Woverride_init;
extern int Woverride_init_all;
extern int Woverride_init_whole_range;
extern int Wparen_string;
extern int Wpast_deep_designator;
extern int Wpedantic;
extern int Wpointer_arith;
extern int Wpointer_to_int_cast;
extern int Wptr_subtraction_blows;
extern int Wreturn_void;
extern int Wshadow;
extern int Wshift_count_negative;
extern int Wshift_count_overflow;
extern int Wsizeof_bool;
extern int Wsparse_error;
extern int Wstrict_prototypes;
extern int Wtautological_compare;
extern int Wtransparent_union;
extern int Wtypesign;
extern int Wundef;
extern int Wuninitialized;
extern int Wunion_cast;
extern int Wuniversal_initializer;
extern int Wunknown_attribute;
extern int Wvla;

extern char **handle_switch(char *arg, char **next);
extern void handle_switch_finalize(void);

#endif
