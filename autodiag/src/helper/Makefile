CC ?= gcc
CXX ?= g++

CFLAGS ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -std=c11
CXXFLAGS ?= -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L -Wall -Wextra -std=c++17
PIE_CFLAGS ?= -fPIE
PIC_CFLAGS ?= -fPIC
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

all: libivi_diag.so ivi_diag_runner ivi_update_runner

libivi_diag.so: libs/ivi_diag.o
	$(CC) -shared -Wl,-z,relro,-z,now -o $@ libs/ivi_diag.o

libs/ivi_diag.o: libs/ivi_diag.c libs/ivi_diag.h
	$(CC) $(CFLAGS) $(PIC_CFLAGS) -c libs/ivi_diag.c -o libs/ivi_diag.o

ivi_diag_runner: ivi_diag_runner.o libivi_diag.so
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -o $@ ivi_diag_runner.o -L. -livi_diag $(LDFLAGS) -Wl,-rpath,'/tmp:$$ORIGIN/../lib'

ivi_diag_runner.o: ivi_diag_runner.c libs/ivi_diag.h
	$(CC) $(CFLAGS) $(PIE_CFLAGS) -c ivi_diag_runner.c -o ivi_diag_runner.o

ivi_update_runner: ivi_update_runner.o
	$(CXX) $(CXXFLAGS) $(PIE_CFLAGS) -o $@ ivi_update_runner.o $(LDFLAGS) -lssl -lcrypto -lz

ivi_update_runner.o: ivi_update_runner.cpp
	$(CXX) $(CXXFLAGS) $(PIE_CFLAGS) -c ivi_update_runner.cpp -o ivi_update_runner.o

clean:
	rm -f libs/ivi_diag.o libivi_diag.so ivi_diag_runner.o ivi_diag_runner ivi_update_runner.o ivi_update_runner

.PHONY: all clean
