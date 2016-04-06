obj-m += af_ktls.o

all: module insmod

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

insmod: module
	# uncomment if you want to have symbols for perf
	#sudo cp af_ktls.ko /lib/modules/`uname -r`/extra
	sudo rmmod af_ktls.ko 2>/dev/null; sudo insmod af_ktls.ko

rmmod:
	sudo rmmod af_ktls.ko

clean:
	sudo rmmod af_ktls.ko; make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: insmod rmmod clean

