obj-m += af_ktls.o
ccflags-y := -O0 -g3
all: module

module:
	make -C ~/ubuntu-xenial M=$(PWD) modules
clean:
	make -C ~/ubuntu-xenial M=$(PWD) clean
