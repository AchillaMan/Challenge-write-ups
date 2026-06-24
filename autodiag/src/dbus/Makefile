CXX ?= g++
PKG_CONFIG ?= pkg-config

CXXFLAGS ?= -O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -std=c++17
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
DBUS_CFLAGS := $(shell $(PKG_CONFIG) --cflags dbus-1)
DBUS_LIBS := $(shell $(PKG_CONFIG) --libs dbus-1)

all: ivi_dbusd

ivi_dbusd: ivi_dbusd.o
	$(CXX) $(CXXFLAGS) -o $@ ivi_dbusd.o $(LDFLAGS) $(DBUS_LIBS)

ivi_dbusd.o: ivi_dbusd.cpp ivi_dbus_iface.h
	$(CXX) $(CXXFLAGS) $(DBUS_CFLAGS) -c ivi_dbusd.cpp -o ivi_dbusd.o

clean:
	rm -f ivi_dbusd.o ivi_dbusd

.PHONY: all clean
