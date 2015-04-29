obj-m += pdsfw.o

all: pdscli pdsfw

pdscli:
	g++ -g -Wall firewall_parser.tab.c lex.yy.c firewall.c -lfl -o pdscli


pdsfw:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: cpdscli cpdsfw

cpdscli:
	rm -f pdscli

cpdsfw:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean