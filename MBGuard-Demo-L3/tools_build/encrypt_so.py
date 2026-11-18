# 내부 모듈(libmbguard_lv2.so)을 ChaCha20으로 암호화해 assets/libmbguard_lv2.so.enc 생성(로더와 동일 키/논스).
# 사용: py encrypt_so.py <plain_inner.so> <out.enc>
import sys, struct

# 로더(loader.cpp)와 반드시 동일.
KEY   = b"MBGuard-L3-demo-key-0123456789AB"  # 32
NONCE = b"mbg-nonce-01"                       # 12
assert len(KEY) == 32 and len(NONCE) == 12

def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] ^= s[a]; s[d] = _rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] ^= s[c]; s[b] = _rotl(s[b], 7)

def _block(key, nonce, ctr):
    const = b"expand 32-byte k"
    st = list(struct.unpack("<4I", const) +
              struct.unpack("<8I", key) +
              (ctr,) +
              struct.unpack("<3I", nonce))
    work = st[:]
    for _ in range(10):
        _qr(work, 0, 4, 8, 12); _qr(work, 1, 5, 9, 13)
        _qr(work, 2, 6, 10, 14); _qr(work, 3, 7, 11, 15)
        _qr(work, 0, 5, 10, 15); _qr(work, 1, 6, 11, 12)
        _qr(work, 2, 7, 8, 13); _qr(work, 3, 4, 9, 14)
    out = [(work[i] + st[i]) & 0xffffffff for i in range(16)]
    return struct.pack("<16I", *out)

def chacha20_xor(key, nonce, ctr0, data):
    out = bytearray(len(data))
    ctr = ctr0
    for off in range(0, len(data), 64):
        ks = _block(key, nonce, ctr)
        chunk = data[off:off + 64]
        for i in range(len(chunk)):
            out[off + i] = chunk[i] ^ ks[i]
        ctr += 1
    return bytes(out)

def _kat():
    # RFC 8439 §2.4.2 known-answer (counter=1) — C/Python 구현 일치 보증.
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only "
          b"one tip for the future, sunscreen would be it.")
    ct = chacha20_xor(key, nonce, 1, pt)
    exp = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    assert ct == exp, "ChaCha20 KAT FAILED"

def main():
    _kat()
    if len(sys.argv) != 3:
        print("usage: py encrypt_so.py <plain_inner.so> <out.enc>"); sys.exit(2)
    with open(sys.argv[1], "rb") as f:
        plain = f.read()
    enc = chacha20_xor(KEY, NONCE, 0, plain)
    with open(sys.argv[2], "wb") as f:
        f.write(enc)
    assert enc[:4] != b"\x7fELF", "암호문이 평문처럼 보임(암호화 실패)"
    print(f"encrypted {len(plain)} bytes -> {sys.argv[2]} (KAT ok)")

if __name__ == "__main__":
    main()
