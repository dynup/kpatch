#include <linux/ftrace.h>

#define KPATCH_MAX_FUNCS	256

struct kpatch_func {
	unsigned long old_func_addr;
	unsigned long new_func_addr;
	char *old_func_name;
	unsigned long old_func_addr_end;
	struct module *mod;
};

struct kpatch_rela {
	unsigned long dest; /* TODO share struct header file with elfdiff */
	unsigned long src;
	unsigned long type;
};

struct kpatch_patch {
	unsigned long new;
	unsigned long orig; /* TODO eventually add name of symbol so we can verify it with kallsyms */
	unsigned long orig_end; /* TODO: rename this struct to kpatch_func, embed it within original kpatch_func, and rename original kpatch_func to kpatch_func_reg? */
};

void kpatch_trampoline(unsigned long ip, unsigned long parent_ip,
		       struct ftrace_ops *op, struct pt_regs *regs);
int kpatch_register(struct module *mod, void *kpatch_relas,
		    void *kpatch_relas_end, void *kpatch_patches,
		    void *kpatch_patches_end);
int kpatch_unregister(struct module *mod);
void ftrace_hacks(void);
