KPATCH_BUILD = /home/sjennings/projects/linux
KPATCH_OBJ = /home/sjennings/projects/obj
KPATCH_MODULES = $(PWD)
KPATCH_MAKE = $(MAKE) -C $(KPATCH_BUILD) O=$(KPATCH_OBJ) M=$(KPATCH_MODULES)

obj-m += kpatch-patch.o

kpatch-patch-objs += kpatch-patch-hook.o kpatch.lds ../output.kpatch_gen

all: kpatch-patch.ko

kpatch-patch.ko:
	$(KPATCH_MAKE) kpatch-patch.ko

kpatch-patch-hook.o: kpatch-patch-hook.c
	$(KPATCH_MAKE) kpatch-patch-hook.o

clean:
	$(RM) -Rf .*.o.cmd .*.ko.cmd .tmp_versions *.o *.ko *.mod.c \
	Module.symvers
