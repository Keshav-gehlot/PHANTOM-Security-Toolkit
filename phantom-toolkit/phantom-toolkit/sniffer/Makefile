CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -Iinclude -D_DEFAULT_SOURCE
TARGET  = phantom-sniffer
SRCS    = src/main.c src/decode.c src/filter.c src/display.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: clean
