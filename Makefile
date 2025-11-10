CC ?= gcc
CFLAGS += -I./include -Wall -Wextra -g
LDFLAGS +=

# Direktori Output
BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin
OBJ_DIR = $(BUILD_DIR)/obj

# Source files
SRCS := $(wildcard core/*.c) $(wildcard os_specific/*.c)
OBJS := $(SRCS:%.c=$(OBJ_DIR)/%.o)

# Nama target utama (library statis untuk saat ini)
TARGET_LIB = $(BUILD_DIR)/libretools.a

.PHONY: all clean prepare directories

all: directories $(TARGET_LIB)

directories:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)/core
	@mkdir -p $(OBJ_DIR)/os_specific

# Build library statis dari objek
$(TARGET_LIB): $(OBJS)
	@echo "[AR] Membuat library $@"
	@ar rcs $@ $^

# Aturan kompilasi objek
$(OBJ_DIR)/%.o: %.c
	@echo "[CC] Mengompilasi $<"
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Membersihkan build..."
	@rm -rf $(BUILD_DIR)

init:
	mkdir -p core interfaces os_specific tests examples docs include/retools