CC=g++
CFLAGS=-g -Wall

firewall:
	$(CC) $(CFLAGS) firewall_parser.tab.c lex.yy.c firewall.c -lfl -o firewall

clean:
	$(RM) firewall
