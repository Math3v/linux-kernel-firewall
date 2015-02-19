#!/bin/bash

rm snazzle.tab.c
rm lex.yy.c

bison -d snazzle.y
flex snazzle.l
#g++ snazzle.tab.c lex.yy.c -lfl -o snazzle
g++ snazzle.tab.c lex.yy.c test.c -lfl -o snazzle
