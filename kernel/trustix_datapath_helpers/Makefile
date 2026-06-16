ifneq ($(KERNELRELEASE),)
obj-m += trustix_datapath_helpers.o
ifeq ($(BASIC),1)
trustix_datapath_helpers-y := trustix_datapath_helpers_main.o
ccflags-y += -DTRUSTIX_DATAPATH_HELPERS_BASIC=1
else
trustix_datapath_helpers-y := trustix_datapath_helpers_main.o trustix_datapath_helpers_kfuncs.o
endif
else

KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_ARGS := M=$(CURDIR)
TRUSTIX_CRYPTO_MODULE_DIR ?= $(patsubst %/trustix_datapath_helpers,%/trustix_crypto,$(CURDIR))
TRUSTIX_CRYPTO_MODULE_SYMVERS ?= $(TRUSTIX_CRYPTO_MODULE_DIR)/Module.symvers
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
ifneq ($(wildcard $(TRUSTIX_CRYPTO_MODULE_SYMVERS)),)
KBUILD_ARGS += KBUILD_EXTRA_SYMBOLS=$(TRUSTIX_CRYPTO_MODULE_SYMVERS)
endif

prepare-btf-base:
	@if [ ! -r "$(KDIR)/vmlinux" ] && [ -r "$(VMLINUX_BTF)" ]; then \
		ln -sfn "$(VMLINUX_BTF)" "$(KDIR)/vmlinux" 2>/dev/null || true; \
	fi

all: prepare-btf-base
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) modules

basic: prepare-btf-base
	$(MAKE) BASIC=1 -C $(KDIR) $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean

install: all
	install -d $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra
	install -m 0644 trustix_datapath_helpers.ko $(INSTALL_MOD_PATH)/lib/modules/$(TARGET_KERNELRELEASE)/extra/trustix_datapath_helpers.ko
	@if [ -n "$(INSTALL_MOD_PATH)" ]; then \
		depmod -a -b "$(INSTALL_MOD_PATH)" "$(TARGET_KERNELRELEASE)"; \
	else \
		depmod -a "$(TARGET_KERNELRELEASE)"; \
	fi

load: all
	insmod ./trustix_datapath_helpers.ko

unload:
	-rmmod trustix_datapath_helpers

.PHONY: all basic clean install load unload prepare-btf-base
endif
