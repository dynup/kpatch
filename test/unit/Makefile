ARCH=$(shell uname -m)

all: Makefile.include $(ARCH)/Makefile
	$(MAKE) -C $(ARCH)

clean: Makefile.include $(ARCH)/Makefile
	$(MAKE) -C $(ARCH) clean
