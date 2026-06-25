CC      = gcc
CFLAGS  = -std=gnu11 -Wall -Wextra -O2 -Iinclude -D_POSIX_C_SOURCE=200112L
LDFLAGS = -lpthread
TARGET  = phantom-httpd
SRCS    = src/main.c src/server.c src/http_parser.c src/router.c \
          src/response.c src/mime.c src/logger.c

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
