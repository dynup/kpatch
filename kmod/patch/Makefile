KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) M=$(PWD) CFLAGS_MODULE='$(CFLAGS_MODULE)'
LDFLAGS += $(KPATCH_LDFLAGS)

obj-m += $(KPATCH_NAME).o
ldflags-y += -T $(src)/kpatch.lds
targets += kpatch.lds

$(KPATCH_NAME)-objs += patch-hook.o output.o

all: $(KPATCH_NAME).ko

$(KPATCH_NAME).ko:
	$(KPATCH_MAKE)

$(obj)/$(KPATCH_NAME).o: $(src)/kpatch.lds

patch-hook.o: patch-hook.c kpatch-patch-hook.c livepatch-patch-hook.c
	$(KPATCH_MAKE) patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
