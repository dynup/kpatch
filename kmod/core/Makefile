# make rules
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KERNELRELEASE := $(lastword $(subst /, , $(dir $(patsubst %/,%,$(KPATCH_BUILD)))))
THISDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

ifeq ($(wildcard $(KPATCH_BUILD)),)
$(error $(KPATCH_BUILD) doesn\'t exist.  Try installing the kernel-devel-$(KERNELRELEASE) RPM or linux-headers-$(KERNELRELEASE) DEB.)
endif

KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(THISDIR)

kpatch.ko: core.c
	$(KPATCH_MAKE) modules

all: kpatch.ko

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers


# kbuild rules
obj-m := kpatch.o
kpatch-y := core.o shadow.o
