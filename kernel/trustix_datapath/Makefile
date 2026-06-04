ifneq ($(KERNELRELEASE),)
obj-m += trustix_datapath.o
else

KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_ARGS := M=$(CURDIR)
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
KDIR_NOSLASH := $(patsubst %/,%,$(KDIR))
KDIR_MODULES_KERNELRELEASE := $(notdir $(patsubst %/source,%,$(patsubst %/build,%,$(KDIR_NOSLASH))))
TARGET_KERNELRELEASE ?= $(if $(filter /lib/modules/%/build /lib/modules/%/source,$(KDIR_NOSLASH)),$(KDIR_MODULES_KERNELRELEASE),$(shell $(MAKE) -s -C $(KDIR) kernelrelease 2>/dev/null || uname -r))
.DEFAULT_GOAL := all
ifneq ($(ARCH),)
KBUILD_ARGS += ARCH=$(ARCH)
endif
ifneq ($(CROSS_COMPILE),)
KBUILD_ARGS += CROSS_COMPILE=$(CROSS_COMPILE)
endif

prepare-btf-base:
	@if [ ! -r "$(KDIR)/vmlinux" ] && [ -r "$(VMLINUX_BTF)" ]; then \
		ln -sfn "$(VMLINUX_BTF)" "$(KDIR)/vmlinux" 2>/dev/null || true; \
	fi

all: prepare-btf-base
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean

install: all
	install -d $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra
	install -m 0644 trustix_datapath.ko $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra/trustix_datapath.ko
	@if [ -n "$(INSTALL_MOD_PATH)" ]; then \
		depmod -a -b "$(INSTALL_MOD_PATH)" "$(TARGET_KERNELRELEASE)"; \
	else \
		depmod -a "$(TARGET_KERNELRELEASE)"; \
	fi

load: all
	insmod ./trustix_datapath.ko

unload:
	-rmmod trustix_datapath

.PHONY: all clean install load unload prepare-btf-base
endif
