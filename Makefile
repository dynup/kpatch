KDIR ?= /home/jpoimboe/git/linux
KPATCH_GENERATED ?= kpatch-generated.o
KMOD_DIR ?= /home/jpoimboe/kpatch/kmod
OBJ_ORIG = /home/jpoimboe/kpatch-test/meminfo.o
OBJ_PATCHED = /home/jpoimboe/kpatch-test/meminfo.o.patched
VMLINUX_ORIG = /home/jpoimboe/kpatch-test/vmlinux

all:
	$(MAKE) -C elf-diff-copy
	elf-diff-copy/elf-diff-copy $(OBJ_ORIG) $(OBJ_PATCHED) -v $(VMLINUX_ORIG) -o $(KMOD_DIR)/$(KPATCH_GENERATED)
	$(MAKE) -C $(KDIR) M=$(KMOD_DIR) kpatch-module.o
	ld -m elf_x86_64 -r -o $(KMOD_DIR)/kpatch-combined.o $(KMOD_DIR)/kpatch-module.o $(KMOD_DIR)/$(KPATCH_GENERATED) $(KMOD_DIR)/kpatch.lds
	$(MAKE) -C $(KDIR) M=$(KMOD_DIR)
