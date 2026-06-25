CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -Iinclude -D_POSIX_C_SOURCE=200112L
TARGET  = phantom-arp
SRCS    = src/main.c src/monitor.c src/spoof.c src/arp_utils.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: clean
