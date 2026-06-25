CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -Iinclude -D_POSIX_C_SOURCE=200112L
LDFLAGS = -lpthread
TARGET  = phantom-scan
SRCS    = src/main.c src/connect_scan.c src/syn_scan.c \
          src/service_detect.c src/os_detect.c src/output.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
