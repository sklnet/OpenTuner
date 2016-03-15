OUTPUT_KO = $(PWD)/../build/$(BOX)
obj-m += otuner_drv.o
obj-m += nim_sockets.o

otuner_drv-objs := \
	otunerc_ctrldev.o \
	otunerc_main.o \
	otunerc_proxydmx.o \
	otunerc_proxyfe.o \
	logs.o

nim_sockets-objs := \
	nim_sockets_proc.o \
	logs.o

EXTRA_INCLUDE =-I$(KERNEL_PATH) -I$(KERNEL_PATH)/include -I$(KERNEL_PATH)/drivers
EXTRA_CFLAGS =-DFT_CREATE_PROCESS -DINSIDE_KERNEL_SPACE -o3 $(EXTRA_INCLUDE) -ldvb-core $(OWN_EXTRA_CFLAGS)

MODULE_SOURCE ?= $(PWD)

all:
	@echo "########################### PATH=$(PATH) ###########################"
	@echo "########################### Create module file: $(obj-m) ###########################"
	@echo "########################### $(CROSS_COMPILE) ###########################"
	@echo "########################### $(KERNEL_PATH) ###########################"
	@echo "########################### $(GCC) ###########################"
	$(MAKE) -w -C $(KERNEL_PATH) SUBDIRS=$(PWD) CROSS_COMPILE=$(CROSS_COMPILE) modules
	@mkdir -p $(OUTPUT_KO)
	mv *.ko $(OUTPUT_KO)/
	rm -f *.o
	rm -f *.mod.c
	$(MAKE) -w -C $(KERNEL_PATH) M=$(MODULE_SOURCE) CROSS_COMPILE=$(CROSS_COMPILE) clean

clean:
	@echo "########################### PATH=$(PATH) ###########################"
	@echo "########################### Clean module file: $(obj-m) ###########################"
	rm -f $(OUTPUT_KO)/*.ko
	rm -f *.o
	rm -f *.mod.c
	$(MAKE) -w -C $(KERNEL_PATH) M=$(MODULE_SOURCE) CROSS_COMPILE=$(CROSS_COMPILE) clean