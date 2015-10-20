KPATCH_NAME ?= patch
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD)
KPATCH_TYPE ?= kpatch

obj-m += $(KPATCH_TYPE)-$(KPATCH_NAME).o

$(KPATCH_TYPE)-$(KPATCH_NAME)-objs += patch-hook.o $(KPATCH_TYPE).lds output.o

all: $(KPATCH_TYPE)-$(KPATCH_NAME).ko

$(KPATCH_TYPE)-$(KPATCH_NAME).ko:
	$(KPATCH_MAKE) $(KPATCH_TYPE)-$(KPATCH_NAME).ko

patch-hook.o: patch-hook.c $(KPATCH_TYPE)-patch-hook.c
	$(KPATCH_MAKE) patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
