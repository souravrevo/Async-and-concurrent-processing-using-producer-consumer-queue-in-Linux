obj-m += sys_xjob.o 

all: xhw3 xjob

xhw3: xhw3.c
	gcc -Wall -Werror -I/lib/modules/$(shell uname -r)/build/arch/x86/include xhw3.c -o xhw3

xjob:	
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xhw3
