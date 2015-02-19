#!/bin/bash

rm firewall_parser.tab.c
rm firewall_parser.tab.h
rm lex.yy.c

bison -d firewall_parser.y
flex firewall_lexer.l
