#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

static const char *kPublicKeyPath = "/etc/ivi/update_public.pem";
static const size_t RSA_BYTES = 256;
static const size_t SIG_BYTES = 256;
static const size_t KEY_BLOB_BYTES = 256;
static const size_t AES_KEY_BYTES = 32;
static const size_t AES_BLOCK = 16;

extern char **environ;

static uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static std::vector<uint8_t> sha256(const uint8_t *data, size_t len) {
    std::vector<uint8_t> out(SHA256_DIGEST_LENGTH);
    SHA256(data, len, out.data());
    return out;
}

static std::vector<uint8_t> base64_decode(std::string input) {
    std::string clean;
    clean.reserve(input.size());
    for (char c : input) {
        if (!std::isspace((unsigned char)c)) {
            clean.push_back(c);
        }
    }
    if (clean.empty() || (clean.size() % 4) != 0) {
        throw std::runtime_error("invalid base64 length");
    }

    std::vector<uint8_t> out((clean.size() * 3) / 4 + 4);
    int n = EVP_DecodeBlock(out.data(), (const unsigned char *)clean.data(),
                            (int)clean.size());
    if (n < 0) {
        throw std::runtime_error("base64 decode failed");
    }

    size_t pad = 0;
    if (!clean.empty() && clean[clean.size() - 1] == '=') {
        pad++;
    }
    if (clean.size() > 1 && clean[clean.size() - 2] == '=') {
        pad++;
    }

    if ((size_t)n < pad) {
        throw std::runtime_error("base64 padding error");
    }
    out.resize((size_t)n - pad);
    return out;
}

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

static std::vector<uint8_t> aes256_cbc_decrypt_zero_iv(const std::vector<uint8_t> &ct,
                                                        const uint8_t key32[AES_KEY_BYTES]) {
    if (ct.size() % AES_BLOCK != 0) {
        throw std::runtime_error("ciphertext not multiple of AES block");
    }

    AES_KEY aes_key;
    if (AES_set_decrypt_key(key32, 256, &aes_key) != 0) {
        throw std::runtime_error("AES_set_decrypt_key failed");
    }

    std::vector<uint8_t> pt(ct.size());
    uint8_t iv[AES_BLOCK];
    memset(iv, 0, sizeof(iv));
    AES_cbc_encrypt(ct.data(), pt.data(), ct.size(), &aes_key, iv, AES_DECRYPT);
    return pt;
}

static std::vector<uint8_t> pkcs7_unpad(std::vector<uint8_t> data) {
    if (data.empty()) {
        throw std::runtime_error("empty plaintext");
    }
    uint8_t pad = data.back();
    if (pad == 0 || pad > AES_BLOCK) {
        throw std::runtime_error("bad padding");
    }
    if (data.size() < pad) {
        throw std::runtime_error("bad padding size");
    }
    for (size_t i = 0; i < pad; i++) {
        if (data[data.size() - 1 - i] != pad) {
            throw std::runtime_error("bad padding bytes");
        }
    }
    data.resize(data.size() - pad);
    return data;
}

static std::vector<uint8_t> gunzip_all(const std::vector<uint8_t> &gz) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        throw std::runtime_error("inflateInit2 failed");
    }

    zs.next_in = (Bytef *)gz.data();
    zs.avail_in = (uInt)gz.size();

    std::vector<uint8_t> out(1024);
    int ret;
    size_t total = 0;
    do {
        if (total == out.size()) {
            out.resize(out.size() * 2);
        }
        zs.next_out = (Bytef *)(out.data() + total);
        zs.avail_out = (uInt)(out.size() - total);

        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&zs);
            throw std::runtime_error("inflate failed");
        }
        total = out.size() - zs.avail_out;
    } while (ret != Z_STREAM_END);

    inflateEnd(&zs);
    out.resize(total);
    return out;
}

static void write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("write failed");
        }
        if (n == 0) {
            throw std::runtime_error("short write");
        }
        off += (size_t)n;
    }
}

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

static int exec_payload_memfd(const std::vector<uint8_t> &payload) {
    int fd = memfd_create("ivi_update_payload", 0);
    if (fd < 0) {
        perror("memfd_create");
        return 1;
    }
    if (fchmod(fd, 0755) != 0) {
        perror("fchmod");
        close(fd);
        return 1;
    }
    try {
        write_all(fd, payload.data(), payload.size());
    } catch (const std::exception &e) {
        fprintf(stderr, "write payload failed: %s\n", e.what());
        close(fd);
        return 1;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek");
        close(fd);
        return 1;
    }

    char *const argv[] = {const_cast<char *>("ivi_update_payload"), nullptr};
    if (execveat(fd, "", argv, environ, AT_EMPTY_PATH) != 0) {
        if (errno != ENOSYS) {
            perror("execveat");
        }
        fexecve(fd, argv, environ);
        perror("fexecve");
    }
    close(fd);
    return 1;
}

int main(int argc, char **argv) {
    uid_t eu = geteuid();
    gid_t eg = getegid();
    if (setresgid(eg, eg, eg) != 0) {
        perror("setresgid");
        return 1;
    }
    if (setresuid(eu, eu, eu) != 0) {
        perror("setresuid");
        return 1;
    }

    if (argc != 2) {
        fprintf(stderr, "usage: %s <update_base64>\n", argv[0]);
        return 2;
    }

    try {
        auto payload = decode_update_payload(argv[1]);
        return exec_payload_memfd(payload);
    } catch (const std::exception &e) {
        fprintf(stderr, "update failed: %s\n", e.what());
        return 1;
    }
}
