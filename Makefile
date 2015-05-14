# Optimization is very important to this running at a sane speed

mpx-mini-test: mpx-dig.c mpx-mini-test.c
	gcc -O3 -Wall -DDEBUG_LEVEL=0 -DMPX_DIG_SELF=1 -g -o mpx-mini-test mpx-dig.c mpx-mini-test.c


