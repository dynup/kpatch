KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)
LDFLAGS += $(KPATCH_LDFLAGS)

# ppc64le kernel modules are expected to compile with the
# -mcmodel=large flag.  This enables 64-bit relocations
# instead of a 32-bit offset from the TOC pointer.
PROCESSOR = $(shell uname -m)
ifeq ($(PROCESSOR), ppc64le)
KBUILD_CFLAGS_MODULE += -mcmodel=large
endif

obj-m += $(KPATCH_NAME).o
ldflags-y += -T $(src)/kpatch.lds

$(KPATCH_NAME)-objs += patch-hook.o kpatch.lds output.o

all: $(KPATCH_NAME).ko

$(KPATCH_NAME).ko:
	$(KPATCH_MAKE) $(KPATCH_NAME).ko

patch-hook.o: patch-hook.c kpatch-patch-hook.c livepatch-patch-hook.c
	$(KPATCH_MAKE) patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
