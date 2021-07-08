__kpatch_funcs = ADDR(.kpatch.funcs);
__kpatch_funcs_end = ADDR(.kpatch.funcs) + SIZEOF(.kpatch.funcs);

#ifdef __KPATCH_MODULE__
__kpatch_dynrelas = ADDR(.kpatch.dynrelas);
__kpatch_dynrelas_end = ADDR(.kpatch.dynrelas) + SIZEOF(.kpatch.dynrelas);
__kpatch_checksum = ADDR(.kpatch.checksum);
#endif

SECTIONS
{
  .text.unlikely.livepatch : {
    *(.text.unlikely.*)
  }

  .text.livepatch : {
    *(.text.*)
  }

  .rodata.str1.1 : {
    *(.rodata.str1.1)
    *(.rodata.*.str1.1)
  }

  .rodata.str1.8 : {
    *(.rodata.str1.8)
    *(.rodata.*.str1.8)
  }

  .rodata : {
    *(.rodata)
    *(.rodata.__func__.*)
  }

  .kpatch.callbacks.pre_patch : {
    __kpatch_callbacks_pre_patch = . ;
    *(.kpatch.callbacks.pre_patch)
    __kpatch_callbacks_pre_patch_end = . ;
    /*
     * Pad the end of the section with zeros in case the section is empty.
     * This prevents the kernel from discarding the section at module
     * load time. __kpatch_callbacks_pre_patch_end will still point to the
     * end of the section before the padding.  If the
     * .kpatch.callbacks.pre_patch section is empty,
     * __kpatch_callbacks_pre_patch equals __kpatch_callbacks_pre_patch_end.
     */
    QUAD(0);
  }
  .kpatch.callbacks.post_patch : {
    __kpatch_callbacks_post_patch = . ;
    *(.kpatch.callbacks.post_patch)
    __kpatch_callbacks_post_patch_end = . ;
    QUAD(0);
  }
  .kpatch.callbacks.pre_unpatch : {
    __kpatch_callbacks_pre_unpatch = . ;
    *(.kpatch.callbacks.pre_unpatch)
    __kpatch_callbacks_pre_unpatch_end = . ;
    QUAD(0);
  }
  .kpatch.callbacks.post_unpatch : {
    __kpatch_callbacks_post_unpatch = . ;
    *(.kpatch.callbacks.post_unpatch)
    __kpatch_callbacks_post_unpatch_end = . ;
    QUAD(0);
  }
  .kpatch.force : {
    __kpatch_force_funcs = . ;
    *(.kpatch.force)
    __kpatch_force_funcs_end = . ;
    QUAD(0);
  }
}
