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
    /*
     * Pad the end of the section with zeros in case the section is empty.
     * This prevents the kernel from discarding the section at module
     * load time. __kpatch_hooks_load_end will still point to the end of
     * the section before the padding.  If the .kpatch.hooks.load section
     * is empty, __kpatch_hooks_load equals __kpatch_hooks_load_end.
     */
    QUAD(0);
  }
  .kpatch.hooks.unload : {
    __kpatch_hooks_unload = . ;
    *(.kpatch.hooks.unload)
    __kpatch_hooks_unload_end = . ;
    QUAD(0);
  }
  .kpatch.force : {
    __kpatch_force_funcs = . ;
    *(.kpatch.force)
    __kpatch_force_funcs_end = . ;
    QUAD(0);
  }
}
