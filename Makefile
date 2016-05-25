# Optimization is very important to this running at a sane speed

mpx-mini-test: mpx-dig.c mpx-mini-test.c mpx-hw.h mpx-debug.h
	gcc -O3 -Wall -DDEBUG_LEVEL=0 -g -o mpx-mini-test mpx-mini-test.c


clean:
	rm -f mpx-mini-test
