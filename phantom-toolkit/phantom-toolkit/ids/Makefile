CC      = gcc
CFLAGS  = -std=gnu99 -Wall -Wextra -O2 -Iinclude
TARGET  = phantom-ids
SRCS    = src/main.c src/capture.c src/rules.c src/alert.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: clean
