__kpatch_funcs = ADDR(.kpatch.funcs);
__kpatch_funcs_end = ADDR(.kpatch.funcs) + SIZEOF(.kpatch.funcs);
__kpatch_dynrelas = ADDR(.kpatch.dynrelas);
__kpatch_dynrelas_end = ADDR(.kpatch.dynrelas) + SIZEOF(.kpatch.dynrelas);
SECTIONS
{
  .kpatch.hooks.load : {
    __kpatch_hooks_load = . ;
    *(.kpatch.hooks.load)
    __kpatch_hooks_load_end = . ;
    QUAD(0);
  }
  .kpatch.hooks.unload : {
    __kpatch_hooks_unload = . ;
    *(.kpatch.hooks.unload)
    __kpatch_hooks_unload_end = . ;
    QUAD(0);
  }
}
