#ifndef IVI_PROTO_H
#define IVI_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define IVI_MAGIC 0x30495649u
#define IVI_VERSION 1u
#define IVI_MAX_BODY (64u * 1024u)

enum IviOp {
    OP_HELLO = 1,
    OP_CONN = 2,
    OP_RESP = 3,
    OP_CLOSE = 4,
    OP_HEALTHCHECK = 5,
    OP_LISTCONN = 6,
    OP_GETCFG = 7,
    OP_SETCFG = 8,
    OP_GETTIME = 9,
    OP_GETSTATS = 10,
    OP_LOGLEVEL = 11,
    OP_ECHO = 12,
    OP_RESOLVE = 13,
    OP_VERSIONINFO = 14
};

#pragma pack(push, 1)
struct MsgHdr {
    uint32_t magic;
    uint32_t version;
    uint32_t op;
    uint32_t body_len;
    uint32_t req_id;
};

struct MsgResp {
    struct MsgHdr hdr;
    uint32_t status;
};
#pragma pack(pop)

static inline uint32_t to_le32(uint32_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return __builtin_bswap32(v);
#endif
}

static inline uint32_t from_le32(uint32_t v) {
    return to_le32(v);
}

static inline uint64_t to_le64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return __builtin_bswap64(v);
#endif
}

static inline uint64_t from_le64(uint64_t v) {
    return to_le64(v);
}

int recv_request(int fd, struct MsgHdr *hdr, uint8_t **body_out);
int send_response(int fd, uint32_t op, uint32_t req_id, uint32_t status,
                  const void *payload, uint32_t payload_len);

#endif
