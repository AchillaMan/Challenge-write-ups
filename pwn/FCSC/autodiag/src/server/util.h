#ifndef IVI_UTIL_H
#define IVI_UTIL_H

#include <stddef.h>
#include <stdint.h>

int read_n(int fd, void *buf, size_t n);
int write_n(int fd, const void *buf, size_t n);
uint64_t now_mono_ms(void);
uint64_t now_wall_ms(void);
int parse_u32(const uint8_t *buf, size_t len, size_t *off, uint32_t *out);
int parse_u64(const uint8_t *buf, size_t len, size_t *off, uint64_t *out);
int parse_blob(const uint8_t *buf, size_t len, size_t *off, const uint8_t **ptr,
               uint32_t need);
int parse_string(const uint8_t *buf, size_t len, size_t *off, char *dst,
                 size_t dst_sz, uint32_t str_len);

#endif
