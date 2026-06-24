/* Hardening enabled via Makefile:
 * -fPIE -fstack-protector-strong -ftrivial-auto-var-init=zero -D_FORTIFY_SOURCE=2 -fsanitize=bounds-strict
 * + warnings/compat: -Wall -Wextra -std=c11 -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
 * => Remove uninitialized stack variable risk, OOB access, strengthens stack protection,
 *    enables libc fortify checks, and supports PIE/ASLR.
 */

#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"
#include "util.h"

#define LISTEN_PORT 4000
#define MAX_CONN_SLOTS 10
#define MAX_RESP_FRAME 2048
#define MAX_CFG_KEY 32
#define MAX_CFG_VAL 64
#define MAX_RESP_PAYLOAD 2048
#define MAX_HOST_LEN 253
#define DBUS_ADDR "unix:path=/run/ivi/bus.sock"
#define DBUS_SERVICE "com.acme.ivi.ServiceManager"
#define DBUS_PATH "/com/acme/ivi/ServiceManager"
#define DBUS_IFACE "com.acme.ivi.ServiceManager"

enum {
    ST_OK = 0,
    ST_INVALID = 1,
    ST_INTERNAL = 2,
    ST_NOTFOUND = 3,
    ST_UNAVAILABLE = 4
};

struct ConfigEntry {
    const char *key;
    char value[MAX_CFG_VAL];
};

struct ServerState {
    int conn_fds[MAX_CONN_SLOTS];
    int dbus_sock_fd;

    uint64_t conn_tx_msgs[MAX_CONN_SLOTS];
    uint64_t conn_tx_bytes[MAX_CONN_SLOTS];

    DBusConnection *dbus_conn;

    uint64_t rx_msgs;
    uint64_t tx_msgs;
    uint64_t errors;

    uint32_t log_level;
    uint64_t last_ping_ms;

    struct ConfigEntry cfgs[4];
};

static struct ServerState *g_state;

static void close_outbound_slot(struct ServerState *st, int idx) {
    if (idx < 0 || idx >= MAX_CONN_SLOTS) { //proper bounds check 0 - 9
        return;
    }
    if (st->conn_fds[idx] >= 0) { //if idx conn fd is valid:    
        close(st->conn_fds[idx]); //close fd
        st->conn_fds[idx] = -1; //close fd (invalid)
        st->conn_tx_msgs[idx] = 0; //zero out msgs
        st->conn_tx_bytes[idx] = 0; //zero out bytes transmitted
    }
}

static void init_state(struct ServerState *st) {
    memset(st, 0, sizeof(*st)); //init serverstate to 0
    st->dbus_sock_fd = -1;
    for (int i = 0; i < MAX_CONN_SLOTS; i++) {
        st->conn_fds[i] = -1; //set all conn fds to -1 (invalid)
    }
    st->log_level = 1; 
    st->cfgs[0].key = "region";
    snprintf(st->cfgs[0].value, sizeof(st->cfgs[0].value), "eu");
    st->cfgs[1].key = "vehicle_mode";
    snprintf(st->cfgs[1].value, sizeof(st->cfgs[1].value), "normal");
    st->cfgs[2].key = "telemetry_interval";
    snprintf(st->cfgs[2].value, sizeof(st->cfgs[2].value), "60");
    st->cfgs[3].key = "dns_override";
    st->cfgs[3].value[0] = '\0';
}

static void shutdown_state(struct ServerState *st) {
    for (int i = 0; i < MAX_CONN_SLOTS; i++) {
        close_outbound_slot(st, i); //return
    }
    if (st->dbus_conn != NULL) { //if conn exists: close conn
        dbus_connection_close(st->dbus_conn);
        dbus_connection_unref(st->dbus_conn);
        st->dbus_conn = NULL;
    }
    st->dbus_sock_fd = -1;
}

static int safe_ascii(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) {
            return 0;
        }
    }
    return 1;
}

static int find_cfg_idx(struct ServerState *st, const char *key) {
    for (size_t i = 0; i < sizeof(st->cfgs) / sizeof(st->cfgs[0]); i++) {
        if (strcmp(st->cfgs[i].key, key) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int connect_dbus_manager(struct ServerState *st) { 
    DBusError err;
    DBusConnection *conn = NULL;
    int fd = -1;

    dbus_error_init(&err);

    if (st->dbus_conn != NULL) { //if no conn error
        dbus_connection_close(st->dbus_conn); 
        dbus_connection_unref(st->dbus_conn);
        st->dbus_conn = NULL;
        st->dbus_sock_fd = -1;
    }

    conn = dbus_connection_open_private(DBUS_ADDR, &err); //private conn at DBUS_ADDR to "unix:path=/run/ivi/bus.sock"
    if (conn == NULL) { //if no conn error
        if (dbus_error_is_set(&err)) {
            fprintf(stderr, "dbus connect failed: %s\n", err.message);
        }
        dbus_error_free(&err);
        return -1;
    }

    dbus_connection_set_exit_on_disconnect(conn, 0); //if disconnect signal received stay active
    if (!dbus_bus_register(conn, &err)) { //if registerisation failed error
        dbus_connection_close(conn); 
        dbus_connection_unref(conn); 
        dbus_error_free(&err);
        return -1;
    }

    if (!dbus_connection_get_unix_fd(conn, &fd)) { //if no fd available error
        dbus_connection_close(conn);
        dbus_connection_unref(conn);
        dbus_error_free(&err);
        return -1;
    }

    st->dbus_conn = conn;
    st->dbus_sock_fd = fd;
    dbus_error_free(&err);
    return 0; 
}

static int dbus_ping(struct ServerState *st) {
    DBusMessage *req = NULL; //request
    DBusMessage *resp = NULL; //response
    DBusError err; //err
    const char *reply = NULL; 
    int ok = -1;

    if (st->dbus_conn == NULL && connect_dbus_manager(st) != 0) {
        return -1;
    }

    dbus_error_init(&err);
    req = dbus_message_new_method_call(DBUS_SERVICE, DBUS_PATH, DBUS_IFACE, "Ping");
    if (req == NULL) {
        return -1;
    }

    resp = dbus_connection_send_with_reply_and_block(st->dbus_conn, req, 4000, &err);
    dbus_message_unref(req);

    if (resp == NULL) {
        if (dbus_error_is_set(&err)) {
            fprintf(stderr, "dbus ping failed: %s\n", err.message);
        }
        dbus_error_free(&err);
        connect_dbus_manager(st);
        return -1;
    }

    if (!dbus_message_get_args(resp, &err, DBUS_TYPE_STRING, &reply,
                               DBUS_TYPE_INVALID)) {
        dbus_error_free(&err);
        dbus_message_unref(resp);
        return -1;
    }

    if (reply != NULL && strcmp(reply, "pong") == 0) {
        ok = 0;
    }

    dbus_message_unref(resp);
    dbus_error_free(&err);
    return ok;
}

static void maybe_periodic_healthcheck(struct ServerState *st) {
    uint64_t now = now_mono_ms();
    if (st->last_ping_ms == 0 || now - st->last_ping_ms >= 15000) {
        dbus_ping(st);
        st->last_ping_ms = now;
    }
}

static int reserve_conn_slot(struct ServerState *st) {
    for (int i = 0; i < MAX_CONN_SLOTS; i++) {
        if (st->conn_fds[i] < 0) {
            return i;
        }
    }
    return -1;
}

static int open_outbound(const char *host, uint16_t port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *it = NULL;
    char port_str[16];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    for (it = res; it != NULL; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

static int op_hello(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                    const uint8_t *body) {
    uint8_t out[128];
    const char *ver = "IVI Connectivity Broker 1.0";
    uint32_t ver_len = (uint32_t)strlen(ver);
    uint32_t caps = 0x0000001fu;
    uint32_t le_ver_len = to_le32(ver_len);
    uint32_t le_caps = to_le32(caps);
    size_t off = 0;

    (void)st;
    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    memcpy(out + off, &le_ver_len, sizeof(le_ver_len));
    off += sizeof(le_ver_len);
    memcpy(out + off, ver, ver_len);
    off += ver_len;
    memcpy(out + off, &le_caps, sizeof(le_caps));
    off += sizeof(le_caps);

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, (uint32_t)off);
}

static int op_conn(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                   const uint8_t *body) {
    size_t off = 0;
    uint32_t ip_len = 0;
    uint32_t port = 0;
    char ip[128];
    int idx;
    int fd;
    uint32_t le_idx;
    struct ServerState *state;
    
    state = st;

    if (parse_u32(body, hdr->body_len, &off, &ip_len) != 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (ip_len == 0 || ip_len >= sizeof(ip)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_string(body, hdr->body_len, &off, ip, sizeof(ip), ip_len) != 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_u32(body, hdr->body_len, &off, &port) != 0 || off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (!safe_ascii(ip, ip_len) || port == 0 || port > 65535) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    idx = reserve_conn_slot(state);
    if (idx < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_UNAVAILABLE, NULL, 0);
    }

    fd = open_outbound(ip, (uint16_t)port);
    if (fd < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_NOTFOUND, NULL, 0);
    }

    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    state->conn_fds[idx] = fd;
    state->conn_tx_msgs[idx] = 0;
    state->conn_tx_bytes[idx] = 0;

    le_idx = to_le32((uint32_t)idx);
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, &le_idx,
                         sizeof(le_idx));
}

static int op_resp(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                   const uint8_t *body) {
    size_t off = 0;
    size_t conn_id = 0;
    size_t payload_len = 0;
    size_t max_len = 0;
    const uint8_t *payload = NULL;
    int target_fd;
    uint8_t frame[MAX_RESP_FRAME];
    uint32_t sent;
    int64_t idx;

    if (parse_u64(body, hdr->body_len, &off, &conn_id) != 0 ||
        parse_u64(body, hdr->body_len, &off, &payload_len) != 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    if (conn_id > SIZE_MAX || payload_len > SIZE_MAX) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    max_len = (size_t)hdr->body_len - off;
    if (max_len > sizeof(frame)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    idx = (int64_t)conn_id;
    if (idx > MAX_CONN_SLOTS - 1) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    
    target_fd = st->conn_fds[idx];
    if (target_fd < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_NOTFOUND, NULL, 0);
    }

    if (payload_len > sizeof(frame)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    if (parse_blob(body, hdr->body_len, &off, &payload, (uint32_t)max_len) != 0 ||
        off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    memcpy(frame, payload, max_len);
    {
        ssize_t n = send(target_fd, frame, payload_len, 0);
        if (n < 0 || (size_t)n != payload_len) {
            return send_response(client_fd, hdr->op, hdr->req_id, ST_UNAVAILABLE, NULL,
                                 0);
        }
    }

    if (idx >= 0 && idx < MAX_CONN_SLOTS) {
        st->conn_tx_msgs[idx]++;
        st->conn_tx_bytes[idx] += payload_len;
    }

    sent = to_le32((uint32_t)payload_len);
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, &sent, sizeof(sent));
}

static int op_close(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                    const uint8_t *body) {
    size_t off = 0;
    uint32_t conn_id = 0;

    if (parse_u32(body, hdr->body_len, &off, &conn_id) != 0 || off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (conn_id >= MAX_CONN_SLOTS) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    close_outbound_slot(st, (int)conn_id);
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, NULL, 0);
}

static int op_healthcheck(struct ServerState *st, int client_fd,
                          const struct MsgHdr *hdr, const uint8_t *body) {
    const char *text = "dbus-ok";

    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    if (dbus_ping(st) != 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_UNAVAILABLE, NULL,
                             0);
    }
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, text,
                         (uint32_t)strlen(text));
}

static int op_listconn(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                       const uint8_t *body) {
    char out[512];
    size_t pos = 0;

    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    for (int i = 0; i < MAX_CONN_SLOTS; i++) {
        size_t remaining = sizeof(out) - pos;
        if (remaining <= 1) {
            break;
        }
        int written = snprintf(out + pos, remaining,
                      "slot=%d fd=%d tx_msgs=%llu tx_bytes=%llu\n", i,
                      st->conn_fds[i],
                      (unsigned long long)st->conn_tx_msgs[i],
                      (unsigned long long)st->conn_tx_bytes[i]);
        if (written < 0) {
            break;
        }
        if ((size_t)written >= remaining) {
            pos = sizeof(out) - 1;
            break;
        }
        pos += (size_t)written;
    }

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, (uint32_t)pos);
}

static int op_getcfg(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                     const uint8_t *body) {
    size_t off = 0;
    uint32_t key_len = 0;
    char key[MAX_CFG_KEY];
    int idx;

    if (parse_u32(body, hdr->body_len, &off, &key_len) != 0 || key_len == 0 ||
        key_len >= sizeof(key)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_string(body, hdr->body_len, &off, key, sizeof(key), key_len) != 0 ||
        off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    idx = find_cfg_idx(st, key);
    if (idx < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_NOTFOUND, NULL, 0);
    }

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, st->cfgs[idx].value,
                         (uint32_t)strlen(st->cfgs[idx].value));
}

static int op_setcfg(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                     const uint8_t *body) {
    size_t off = 0;
    uint32_t key_len = 0;
    uint32_t val_len = 0;
    char key[MAX_CFG_KEY];
    char val[MAX_CFG_VAL];
    int idx;

    if (parse_u32(body, hdr->body_len, &off, &key_len) != 0 || key_len == 0 ||
        key_len >= sizeof(key)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_string(body, hdr->body_len, &off, key, sizeof(key), key_len) != 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_u32(body, hdr->body_len, &off, &val_len) != 0 || val_len >= sizeof(val)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_string(body, hdr->body_len, &off, val, sizeof(val), val_len) != 0 ||
        off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (!safe_ascii(val, val_len)) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    idx = find_cfg_idx(st, key);
    if (idx < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_NOTFOUND, NULL, 0);
    }

    if (strcmp(key, "telemetry_interval") == 0) {
        for (uint32_t i = 0; i < val_len; i++) {
            if (val[i] < '0' || val[i] > '9') {
                return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL,
                                     0);
            }
        }
    }

    snprintf(st->cfgs[idx].value, sizeof(st->cfgs[idx].value), "%s", val);
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, NULL, 0);
}

static int op_gettime(int client_fd, const struct MsgHdr *hdr, const uint8_t *body) {
    uint64_t out[2];

    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    out[0] = to_le64(now_wall_ms());
    out[1] = to_le64(now_mono_ms());
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, sizeof(out));
}

static int op_getstats(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                       const uint8_t *body) {
    uint64_t out[4];
    uint32_t active = 0;

    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    for (int i = 0; i < MAX_CONN_SLOTS; i++) {
        if (st->conn_fds[i] >= 0) {
            active++;
        }
    }

    out[0] = to_le64(st->rx_msgs);
    out[1] = to_le64(st->tx_msgs);
    out[2] = to_le64(st->errors);
    out[3] = to_le64(active);

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, sizeof(out));
}

static int op_loglevel(struct ServerState *st, int client_fd, const struct MsgHdr *hdr,
                       const uint8_t *body) {
    size_t off = 0;
    uint32_t level = 0;
    uint32_t out[2];

    if (parse_u32(body, hdr->body_len, &off, &level) != 0 || off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (level > 3) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    out[0] = to_le32(st->log_level);
    st->log_level = level;
    out[1] = to_le32(st->log_level);

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, sizeof(out));
}

static int op_echo(int client_fd, const struct MsgHdr *hdr, const uint8_t *body) {
    size_t off = 0;
    uint32_t len = 0;
    const uint8_t *data = NULL;

    if (parse_u32(body, hdr->body_len, &off, &len) != 0 || len > MAX_RESP_PAYLOAD) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_blob(body, hdr->body_len, &off, &data, len) != 0 || off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, data, len);
}

static int op_resolve(int client_fd, const struct MsgHdr *hdr, const uint8_t *body) {
    size_t off = 0;
    uint32_t host_len = 0;
    char host[MAX_HOST_LEN + 1];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char out[INET6_ADDRSTRLEN];
    void *src = NULL;

    if (parse_u32(body, hdr->body_len, &off, &host_len) != 0 || host_len == 0 ||
        host_len > MAX_HOST_LEN) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
    if (parse_string(body, hdr->body_len, &off, host, sizeof(host), host_len) != 0 ||
        off != hdr->body_len) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        if (res != NULL) {
            freeaddrinfo(res);
        }
        return send_response(client_fd, hdr->op, hdr->req_id, ST_NOTFOUND, NULL, 0);
    }

    if (res->ai_family == AF_INET) {
        src = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
    } else if (res->ai_family == AF_INET6) {
        src = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    }

    if (src == NULL || inet_ntop(res->ai_family, src, out, sizeof(out)) == NULL) {
        freeaddrinfo(res);
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INTERNAL, NULL, 0);
    }

    freeaddrinfo(res);
    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out,
                         (uint32_t)strlen(out));
}

static int op_versioninfo(int client_fd, const struct MsgHdr *hdr,
                          const uint8_t *body) {
    char out[256];
    int n;

    if (hdr->body_len != 0 || body != NULL) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }

    n = snprintf(out, sizeof(out),
                 "component=ivi-broker;build=1.0.0;git=0000000;features=dbus,telemetry,"
                 "diag");
    if (n < 0) {
        return send_response(client_fd, hdr->op, hdr->req_id, ST_INTERNAL, NULL, 0);
    }
    if ((size_t)n >= sizeof(out)) {
        n = (int)sizeof(out) - 1;
    }

    return send_response(client_fd, hdr->op, hdr->req_id, ST_OK, out, (uint32_t)n);
}

static int dispatch_request(struct ServerState *st, int client_fd,
                            const struct MsgHdr *hdr, const uint8_t *body) {
    switch (hdr->op) {
        case OP_HELLO:
            return op_hello(st, client_fd, hdr, body); //safe
        case OP_CONN:
            return op_conn(st, client_fd, hdr, body); //safe
        case OP_RESP:
            return op_resp(st, client_fd, hdr, body); //sus oob write
        case OP_CLOSE:
            return op_close(st, client_fd, hdr, body); //safe
        case OP_HEALTHCHECK:
            return op_healthcheck(st, client_fd, hdr, body); //safe
        case OP_LISTCONN:
            return op_listconn(st, client_fd, hdr, body); //safe
        case OP_GETCFG:
            return op_getcfg(st, client_fd, hdr, body); //safe
        case OP_SETCFG:
            return op_setcfg(st, client_fd, hdr, body); //safe
        case OP_GETTIME:
            return op_gettime(client_fd, hdr, body); 
        case OP_GETSTATS:
            return op_getstats(st, client_fd, hdr, body);
        case OP_LOGLEVEL:
            return op_loglevel(st, client_fd, hdr, body);
        case OP_ECHO:
            return op_echo(client_fd, hdr, body);
        case OP_RESOLVE:
            return op_resolve(client_fd, hdr, body);
        case OP_VERSIONINFO:
            return op_versioninfo(client_fd, hdr, body);
        default:
            return send_response(client_fd, hdr->op, hdr->req_id, ST_INVALID, NULL, 0);
    }
}

static void handle_client(struct ServerState *st, int in_fd, int out_fd,
                          int close_in_fd) {
    while (1) {
        struct MsgHdr hdr;
        uint8_t *body = NULL;
        int rc;

        maybe_periodic_healthcheck(st);

        rc = recv_request(in_fd, &hdr, &body);
        if (rc != 0) {
            free(body);
            break;
        }

        st->rx_msgs++;

        rc = dispatch_request(st, out_fd, &hdr, body);
        free(body);

        if (rc != 0) {
            st->errors++;
            break;
        }

        st->tx_msgs++;
    }

    if (close_in_fd) {
        close(in_fd);
    }
}

static int make_listener(uint16_t port) {
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0); //IPv4 stream socket with TCP protocol
    if (fd < 0) {
        return -1; //exit
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        close(fd);
        return -1; //exit
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1; //exit
    }

    if (listen(fd, 16) != 0) {
        close(fd);
        return -1; //exit
    }

    return fd;
}

int main(int argc, char **argv) {
    int use_network = 0;
    int listen_fd;

    if (argc >= 2) {
        if (strcmp(argv[1], "--network") == 0) { //if arg 1 = --network continue
            use_network = 1;
        } else { //terminate
            fprintf(stderr, "usage: %s [--network]\n", argv[0]);
            return 1; 
        }
    }
    
    g_state = (struct ServerState *)mmap(NULL, sizeof(*g_state),
                                         PROT_READ | PROT_WRITE,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_state == MAP_FAILED) {
        perror("mmap ServerState");
        return 1;
    }

    init_state(g_state);

    if (connect_dbus_manager(g_state) != 0) {
        fprintf(stderr, "warning: initial dbus connect failed\n");
    }

    if (!use_network) { //exit
        handle_client(g_state, 0, 1, 0);
        shutdown_state(g_state);
        munmap(g_state, sizeof(*g_state));
        return 0;
    }

    listen_fd = make_listener(LISTEN_PORT); //listener at port 4000
    if (listen_fd < 0) {
        fprintf(stderr, "listen failed on port %d\n", LISTEN_PORT);
        shutdown_state(g_state);
        munmap(g_state, sizeof(*g_state));
        return 1;
    }

    for (;;) { //inf loop
        struct pollfd pfd; 
        int prc;

        pfd.fd = listen_fd;
        pfd.events = POLLIN; //0x001
        pfd.revents = 0;

        prc = poll(&pfd, 1, 1000);
        maybe_periodic_healthcheck(g_state);

        if (prc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (prc == 0) {
            continue;
        }

        if (pfd.revents & POLLIN) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd < 0) {
                continue;
            }
            handle_client(g_state, client_fd, client_fd, 1);
        }
    }

    close(listen_fd);
    shutdown_state(g_state);
    munmap(g_state, sizeof(*g_state));
    return 0;
}
