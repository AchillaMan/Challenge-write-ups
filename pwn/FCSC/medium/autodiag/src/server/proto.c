#include "proto.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

int recv_request(int fd, struct MsgHdr *hdr, uint8_t **body_out) {
    struct MsgHdr wire;

    *body_out = NULL;
    if (read_n(fd, &wire, sizeof(wire)) != 0) {
        return -1;
    }

    hdr->magic = from_le32(wire.magic);
    hdr->version = from_le32(wire.version);
    hdr->op = from_le32(wire.op);
    hdr->body_len = from_le32(wire.body_len);
    hdr->req_id = from_le32(wire.req_id);

    if (hdr->magic != IVI_MAGIC || hdr->version != IVI_VERSION) {
        return -1;
    }
    if (hdr->body_len > IVI_MAX_BODY) {
        return -1;
    }

    if (hdr->body_len > 0) {
        uint8_t *body = (uint8_t *)malloc(hdr->body_len);
        if (body == NULL) {
            return -1;
        }
        if (read_n(fd, body, hdr->body_len) != 0) {
            free(body);
            return -1;
        }
        *body_out = body;
    }

    return 0;
}

int send_response(int fd, uint32_t op, uint32_t req_id, uint32_t status,
                  const void *payload, uint32_t payload_len) {
    struct MsgHdr wire_hdr;
    uint32_t wire_status;
    uint32_t body_len;

    if (payload_len > IVI_MAX_BODY - (uint32_t)sizeof(uint32_t)) {
        errno = EINVAL;
        return -1;
    }

    body_len = (uint32_t)sizeof(uint32_t) + payload_len;

    wire_hdr.magic = to_le32(IVI_MAGIC);
    wire_hdr.version = to_le32(IVI_VERSION);
    wire_hdr.op = to_le32(op);
    wire_hdr.body_len = to_le32(body_len);
    wire_hdr.req_id = to_le32(req_id);

    wire_status = to_le32(status);

    if (write_n(fd, &wire_hdr, sizeof(wire_hdr)) != 0) {
        return -1;
    }
    if (write_n(fd, &wire_status, sizeof(wire_status)) != 0) {
        return -1;
    }
    if (payload_len > 0 && payload != NULL) {
        if (write_n(fd, payload, payload_len) != 0) {
            return -1;
        }
    }

    return 0;
}
