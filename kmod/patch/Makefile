KPATCH_NAME ?= patch
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)
LDFLAGS += $(KPATCH_LDFLAGS)

# ppc64le kernel modules are expected to compiled with
# -mcmodel=large flag. This enable 64-bit relocations,
# instead of 32-bit offset from TOC pointer.
PROCESSOR = $(shell uname -p)
ifeq ($(PROCESSOR), ppc64le)
KBUILD_CFLAGS_MODULE += -mcmodel=large
endif

obj-m += kpatch-$(KPATCH_NAME).o

kpatch-$(KPATCH_NAME)-objs += patch-hook.o kpatch.lds output.o

all: kpatch-$(KPATCH_NAME).ko

kpatch-$(KPATCH_NAME).ko:
	$(KPATCH_MAKE) kpatch-$(KPATCH_NAME).ko

patch-hook.o: patch-hook.c kpatch-patch-hook.c livepatch-patch-hook.c
	$(KPATCH_MAKE) patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
