CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -Iinclude -D_POSIX_C_SOURCE=200112L
TARGET  = phantom-dns
SRCS    = src/main.c src/packet.c src/query.c src/cache.c \
          src/resolve.c src/cli.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: clean
