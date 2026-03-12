CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread

TARGET = blackscan
SRC = blackscan.c
HDR = blackscan.h

VERSION = 1.1

.PHONY: all clean help install uninstall

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "Blackscan v$(VERSION) compilado exitosamente"

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	chmod +s /usr/local/bin/$(TARGET)
	@echo "Instalado en /usr/local/bin/$(TARGET)"

uninstall:
	rm -f /usr/local/bin/$(TARGET)
	@echo "Desinstalado"

help:
	@echo "Blackscan v$(VERSION) - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Compilar (default)"
	@echo "  clean      - Limpiar archivos"
	@echo "  install    - Instalar (requiere root)"
	@echo "  uninstall  - Desinstalar"
	@echo "  help       - Mostrar ayuda"
	@echo ""
	@echo "Uso:"
	@echo "  make               - Compilar"
	@echo "  make clean         - Limpiar"
	@echo "  sudo make install  - Instalar"
