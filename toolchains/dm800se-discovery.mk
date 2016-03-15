export BOX = dm800se
export ARCH = mips
export MAKE = make

BASE_PATH=/home/discovery/build/development/images/openpli30/openpli-openpli-oe-core/build-$(BOX)/tmp/sysroots

export CROSS_COMPILE = mipsel-oe-linux-
export KERNEL_PATH ?= $(BASE_PATH)/$(BOX)/kernel

export GCC = mipsel-oe-linux-gcc
export CXX = mipsel-oe-linux-g++
export LD = mipsel-oe-linux-ld
export CPP = mipsel-oe-linux-cpp

PATH := ${PATH}:$(BASE_PATH)/x86_64-linux/usr/bin/mips32el-oe-linux
CFLAGS="-Wall"