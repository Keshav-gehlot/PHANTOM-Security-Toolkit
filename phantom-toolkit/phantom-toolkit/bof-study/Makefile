# phantom-bof Makefile
CC      = gcc
CFLAGS_VULN    = -std=c11 -Wall -O0 -fno-stack-protector -z execstack -no-pie \
                  -Wno-deprecated-declarations -Wno-implicit-function-declaration
CFLAGS_DEFENDED= -std=c11 -Wall -O2 -fstack-protector-strong \
                  -D_FORTIFY_SOURCE=2 -pie -fPIE -Wformat -Wformat-security
CFLAGS_DEMO    = -std=c11 -Wall -O2

all: vuln defended exploit_demo

vuln: src/vuln.c
	$(CC) $(CFLAGS_VULN) -o $@ $^
	@echo "[!] WARNING: vuln is intentionally exploitable. Educational use only."

defended: src/defended.c
	$(CC) $(CFLAGS_DEFENDED) -o $@ $^

exploit_demo: src/exploit_demo.c
	$(CC) $(CFLAGS_DEMO) -o $@ $^

clean:
	rm -f vuln defended exploit_demo

# Disable ASLR for vuln demo (requires root):
disable-aslr:
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

enable-aslr:
	echo 2 | sudo tee /proc/sys/kernel/randomize_va_space

.PHONY: all clean disable-aslr enable-aslr
