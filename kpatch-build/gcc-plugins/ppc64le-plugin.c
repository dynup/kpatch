#include <error.h>
#include "gcc-common.h"

#define PLUGIN_NAME "ppc64le-plugin"

#if BUILDING_GCC_VERSION < 10000
#define CALL_LOCAL		"*call_local_aixdi"
#define CALL_NONLOCAL		"*call_nonlocal_aixdi"
#define CALL_VALUE_LOCAL	"*call_value_local_aixdi"
#define CALL_VALUE_NONLOCAL	"*call_value_nonlocal_aixdi"
#else
#define CALL_LOCAL		"*call_localdi"
#define CALL_NONLOCAL		"*call_nonlocal_aixdi"
#define CALL_VALUE_LOCAL	"*call_value_localdi"
#define CALL_VALUE_NONLOCAL	"*call_value_nonlocal_aixdi"
#endif

int plugin_is_GPL_compatible;

struct plugin_info plugin_info = {
	.version	= "1",
	.help		= PLUGIN_NAME ": insert nops after local calls\n",
};

static unsigned int ppc64le_plugin_execute(void)
{
	rtx_insn *insn;
	int code;
	const char *name;
	static int nonlocal_code = -1, local_code = -1,
		   value_nonlocal_code = -1, value_local_code = -1;
	static bool initialized = false;

	if (initialized)
		goto found;

	/* Find the rs6000.md code numbers for local and non-local calls */
	initialized = true;
	for (code = 0; code < 1000; code++) {
		name = get_insn_name(code);
		if (!name)
			continue;

		if (!strcmp(name , CALL_LOCAL))
			local_code = code;
		else if (!strcmp(name , CALL_NONLOCAL))
			nonlocal_code = code;
		else if (!strcmp(name, CALL_VALUE_LOCAL))
			value_local_code = code;
		else if (!strcmp(name, CALL_VALUE_NONLOCAL))
			value_nonlocal_code = code;

		if (nonlocal_code != -1 && local_code != -1 &&
		    value_nonlocal_code != -1 && value_local_code != -1)
			goto found;
	}

found:
	if (nonlocal_code == -1 || local_code == -1 ||
	    value_nonlocal_code == -1 || value_local_code == -1) {
		error("%s: cannot find call instruction codes", PLUGIN_NAME);
	}

	/* Convert local calls to non-local */
	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		if (GET_CODE(insn) == CALL_INSN) {
			if (INSN_CODE(insn) == local_code)
				INSN_CODE(insn) = nonlocal_code;
			else if (INSN_CODE(insn) == value_local_code)
				INSN_CODE(insn) = value_nonlocal_code;
		}
	}

	return 0;
}

#define PASS_NAME ppc64le_plugin
#define NO_GATE
#include "gcc-generate-rtl-pass.h"

int plugin_init(struct plugin_name_args *plugin_info,
		struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;

	PASS_INFO(ppc64le_plugin, "vregs", 1, PASS_POS_INSERT_AFTER);

	if (!plugin_default_version_check(version, &gcc_version))
                error(1, 0, PLUGIN_NAME ": incompatible gcc/plugin versions");

	register_callback(plugin_name, PLUGIN_INFO, NULL, &plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
			  &ppc64le_plugin_pass_info);

	return 0;
}

