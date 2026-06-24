CC ?= gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -O0 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -std=c11
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
DBUS_CFLAGS := $(shell $(PKG_CONFIG) --cflags dbus-1)
DBUS_LIBS := $(shell $(PKG_CONFIG) --libs dbus-1)

OBJS = ivi_server.o proto.o util.o

all: ivi_server

ivi_server: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(DBUS_LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(DBUS_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) ivi_server

.PHONY: all clean
