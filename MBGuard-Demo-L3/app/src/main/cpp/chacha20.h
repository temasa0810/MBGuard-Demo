// ChaCha20 (RFC 8439) 키스트림 — 헤더온리. L3 패킹 데모의 복호에 사용(리틀엔디언 전제: ARM64/x86).
#ifndef CHACHA20_H
#define CHACHA20_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline uint32_t cc_rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define CC_QR(a, b, c, d) \
    a += b; d ^= a; d = cc_rotl(d, 16); \
    c += d; b ^= c; b = cc_rotl(b, 12); \
    a += b; d ^= a; d = cc_rotl(d, 8);  \
    c += d; b ^= c; b = cc_rotl(b, 7);

static inline void cc_block(const uint32_t in[16], uint32_t out[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);
    for (int i = 0; i < 10; i++) {
        CC_QR(x[0], x[4], x[8],  x[12])
        CC_QR(x[1], x[5], x[9],  x[13])
        CC_QR(x[2], x[6], x[10], x[14])
        CC_QR(x[3], x[7], x[11], x[15])
        CC_QR(x[0], x[5], x[10], x[15])
        CC_QR(x[1], x[6], x[11], x[12])
        CC_QR(x[2], x[7], x[8],  x[13])
        CC_QR(x[3], x[4], x[9],  x[14])
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

// key=32B, nonce=12B, counter 시작=ctr0. buf[len]에 키스트림 XOR(제자리). 암·복호 동일(스트림).
static inline void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                                uint32_t ctr0, uint8_t *buf, size_t len) {
    uint32_t st[16], ks[16];
    // "expand 32-byte k"를 LE 상수로 직접(평문 문자열이 바이너리에 남지 않게).
    st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    memcpy(&st[4], key, 32);
    st[12] = ctr0;
    memcpy(&st[13], nonce, 12);
    size_t off = 0;
    while (off < len) {
        cc_block(st, ks);
        const uint8_t *kb = (const uint8_t *) ks;
        size_t n = len - off; if (n > 64) n = 64;
        for (size_t i = 0; i < n; i++) buf[off + i] ^= kb[i];
        off += n;
        st[12]++;
    }
}
#endif
