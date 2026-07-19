#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "util.h"

int read_n(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t rv = read(fd, p + off, n - off);
        if (rv == 0) {
            return -1;
        }
        if (rv < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)rv;
    }
    return 0;
}

int write_n(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0;
    while (off < n) {
        ssize_t rv = write(fd, p + off, n - off);
        if (rv < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        off += (size_t)rv;
    }
    return 0;
}

uint64_t now_mono_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

uint64_t now_wall_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

int parse_u32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out) {
    uint32_t raw;
    if (*off + sizeof(raw) > len) {
        return -1;
    }
    memcpy(&raw, buf + *off, sizeof(raw));
    *off += sizeof(raw);
    *out = from_le32(raw);
    return 0;
}

int parse_u64(const uint8_t *buf, size_t len, size_t *off, uint64_t *out) {
    uint64_t raw;
    if (*off + sizeof(raw) > len) {
        return -1;
    }
    memcpy(&raw, buf + *off, sizeof(raw));
    *off += sizeof(raw);
    *out = from_le64(raw);
    return 0;
}

int parse_blob(const uint8_t *buf, size_t len, size_t *off, const uint8_t **ptr,
               uint32_t need) {
    if (*off + need > len) {
        return -1;
    }
    *ptr = buf + *off;
    *off += need;
    return 0;
}

int parse_string(const uint8_t *buf, size_t len, size_t *off, char *dst,
                 size_t dst_sz, uint32_t str_len) {
    const uint8_t *src = NULL;
    if (dst_sz == 0 || str_len + 1 > dst_sz) {
        return -1;
    }
    if (parse_blob(buf, len, off, &src, str_len) != 0) {
        return -1;
    }
    memcpy(dst, src, str_len);
    dst[str_len] = '\0';
    return 0;
}
