KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

progs := dtls-window

check: $(progs)
	./dtls-window

${progs}: LDLIBS += -lcmocka

clean:
	rm -f *.o $(progs) *~

.PHONY: all clean check
