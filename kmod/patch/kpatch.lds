__kpatch_funcs = ADDR(.kpatch.funcs);
__kpatch_funcs_end = ADDR(.kpatch.funcs) + SIZEOF(.kpatch.funcs);
__kpatch_dynrelas = ADDR(.kpatch.dynrelas);
__kpatch_dynrelas_end = ADDR(.kpatch.dynrelas) + SIZEOF(.kpatch.dynrelas);
__kpatch_hooks_load = ADDR(.kpatch.hooks.load);
__kpatch_hooks_load_end = ADDR(.kpatch.hooks.load) + SIZEOF(.kpatch.hooks.load);
__kpatch_hooks_unload = ADDR(.kpatch.hooks.unload);
__kpatch_hooks_unload_end = ADDR(.kpatch.hooks.unload) + SIZEOF(.kpatch.hooks.unload);
