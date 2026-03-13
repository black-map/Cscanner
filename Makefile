# CScanner v1.4 - Advanced Network Scanner Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600

TARGET = cscanner

SOURCES = \
	network/checksum.c \
	network/raw_socket.c \
	network/packet_builder.c \
	network/io_uring_async.c \
	network/adaptive_engine.c \
	network/pipeline_optimizer.c \
	scanners/scanners.c \
	detection/service_detection.c \
	detection/os_fingerprint.c \
	output/color_output.c \
	scripting/lua_scripting.c \
	cli/argument_parser.c \
	cli/main.c

OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) -lpthread -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: all clean install
