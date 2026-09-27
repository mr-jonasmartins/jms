/* JMS 3.0 research artifact — C99 core, POSIX macOS/Linux shell.
 * PBKDF2-HMAC-SHA256 (RFC 8018), ChaCha20-Poly1305 (RFC 8439).
 * Based in part on the author's JMS 2 SHA-256/ChaCha20 implementation.
 * No third-party cryptographic dependencies. Not independently audited.
 * Format JMS3 is incompatible with JMS2. Never overwrites an existing path.
 * Build: cc -std=c99 -O2 -Wall -Wextra -Wpedantic jms.c -o jms
 */
#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>

#define JMS_KEY_SIZE 32u
#define JMS_NONCE_SIZE 12u
#define JMS_DEFAULT_ITERATIONS 600000u
#define JMS_MIN_ITERATIONS 100000u
#define JMS_MAX_ITERATIONS 5000000u
#define JMS_MAX_BYTES UINT64_C(274877906880)
#define JMS_BUFFER_SIZE 65536u
#define JMS_PASSWORD_SIZE 256u
#define JMS_AAD_SIZE 40u
#define JMS_HEADER_SIZE 56u

/* Volatile stores address DSE for this buffer; not register/swap erasure. */
static void secure_memzero(void *ptr, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (n--) *p++ = 0;
}
#define SECURE_ZERO(p,n) secure_memzero((p),(n))

/* Contexto incremental de SHA-256. */

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

/* Contexto de HMAC-SHA256 (estado interno e externo). */

typedef struct {
    sha256_ctx_t inner;
    sha256_ctx_t outer;
} hmac_sha256_ctx_t;

/* Contexto de cifra de fluxo ChaCha20. */

typedef struct {
    uint8_t key[JMS_KEY_SIZE];
    uint8_t nonce[JMS_NONCE_SIZE];
    uint64_t counter;
    uint8_t keystream[64];
    size_t keystream_offset;
} chacha20_ctx_t;

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* Rotacao para direita usada pelo SHA-256. */

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

/* Le/escreve inteiro de 32 bits em little-endian. */

static uint32_t load_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;

    for (int i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + s1 + ch + SHA256_K[i] + m[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
    SECURE_ZERO(m, sizeof(m));
}

/* Inicializa estado do SHA-256. */

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
}

/* Atualiza SHA-256 com dados arbitrarios. */

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/* Finaliza SHA-256 e escreve digest de 32 bytes. */

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8u;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xFFu);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xFFu);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xFFu);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xFFu);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xFFu);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xFFu);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xFFu);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xFFu);
    }
}

/* Atalho para calcular SHA-256 de uma vez. */

static void sha256_once(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
    SECURE_ZERO(&ctx, sizeof(ctx));
}

/*
 * Inicializa HMAC-SHA256 para uma chave.
 * Se a chave for maior que 64 bytes, ela e reduzida via SHA-256.
 */

static void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len) {
    uint8_t key_block[64];
    uint8_t temp_hash[32];
    uint8_t ipad[64];
    uint8_t opad[64];

    memset(key_block, 0, sizeof(key_block));
    if (key_len > 64) {
        sha256_once(key, key_len, temp_hash);
        memcpy(key_block, temp_hash, 32);
    } else {
        memcpy(key_block, key, key_len);
    }

    for (int i = 0; i < 64; ++i) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36u);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5cu);
    }

    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, ipad, sizeof(ipad));

    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, opad, sizeof(opad));
    SECURE_ZERO(key_block, sizeof(key_block));
    SECURE_ZERO(temp_hash, sizeof(temp_hash));
    SECURE_ZERO(ipad, sizeof(ipad));
    SECURE_ZERO(opad, sizeof(opad));
}

/* Alimenta dados no HMAC-SHA256. */

static void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

/* Finaliza HMAC-SHA256. */

static void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t mac[32]) {
    uint8_t inner_hash[32];
    sha256_final(&ctx->inner, inner_hash);
    sha256_update(&ctx->outer, inner_hash, sizeof(inner_hash));
    sha256_final(&ctx->outer, mac);
    SECURE_ZERO(inner_hash, sizeof(inner_hash));
    SECURE_ZERO(ctx, sizeof(*ctx));
}

/*
 * Compara buffers em tempo constante para evitar vazamento por timing.
 * Retorna 1 se iguais, 0 caso contrario.
 */

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* Quarter round do ChaCha20 (operacao base). */

static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8)  | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7)  | (*b >> 25);
}

/* Gera um bloco de keystream de 64 bytes do ChaCha20. */

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t state[16];
    uint32_t working[16];

    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;

    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load_le32(key + (size_t)i * 4u);
    }

    state[12] = counter;
    state[13] = load_le32(nonce + 0);
    state[14] = load_le32(nonce + 4);
    state[15] = load_le32(nonce + 8);

    for (int i = 0; i < 16; ++i) {
        working[i] = state[i];
    }

    for (int i = 0; i < 10; ++i) {
        chacha20_quarter_round(&working[0], &working[4], &working[8], &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9], &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);

        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8], &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }

    for (int i = 0; i < 16; ++i) {
        working[i] += state[i];
        store_le32(out + (size_t)i * 4u, working[i]);
    }
    SECURE_ZERO(state, sizeof(state));
    SECURE_ZERO(working, sizeof(working));
}

/* Inicializa contexto ChaCha20 (contador inicia em 1). */

static void chacha20_init(chacha20_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    memcpy(ctx->key, key, JMS_KEY_SIZE);
    memcpy(ctx->nonce, nonce, JMS_NONCE_SIZE);
    ctx->counter = 1u;
    ctx->keystream_offset = 64u;
}

/* Aplica XOR de keystream sobre o buffer (encripta/decripta). */

static void chacha20_xor(chacha20_ctx_t *ctx, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (ctx->keystream_offset >= 64u) {
            chacha20_block(ctx->key, (uint32_t)ctx->counter++, ctx->nonce, ctx->keystream);
            ctx->keystream_offset = 0u;
        }
        data[i] ^= ctx->keystream[ctx->keystream_offset++];
    }
}

/* PBKDF2 specialized to the 32-byte JMS key (one output block).
 * Precomputed HMAC inner/outer states avoid hashing the pads per iteration. */
static int pbkdf2(const uint8_t *pw, size_t plen, const uint8_t *salt,
                  size_t slen, uint32_t iterations, uint8_t out[32]) {
    hmac_sha256_ctx_t base, work;
    uint8_t u[32], block[4] = {0, 0, 0, 1};
    if (!iterations) return 0;
    hmac_sha256_init(&base, pw, plen);
    work = base;
    hmac_sha256_update(&work, salt, slen);
    hmac_sha256_update(&work, block, sizeof(block));
    hmac_sha256_final(&work, u);
    memcpy(out, u, 32);
    for (uint32_t i = 1; i < iterations; ++i) {
        work = base;
        hmac_sha256_update(&work, u, 32);
        hmac_sha256_final(&work, u);
        for (size_t j = 0; j < 32; ++j) out[j] ^= u[j];
    }
    SECURE_ZERO(&base, sizeof(base));
    SECURE_ZERO(&work, sizeof(work));
    SECURE_ZERO(u, sizeof(u));
    return 1;
}

/* Poly1305: five base-2^26 limbs, uint64_t products, modulo 2^130-5.
 * The reduction and final selection do not branch on secret limb values. */
typedef struct {
    uint32_t r[5], h[5], pad[4];
    uint8_t buffer[16];
    size_t used;
} poly_ctx;

static void poly_init(poly_ctx *p, const uint8_t key[32]) {
    memset(p, 0, sizeof(*p));
    p->r[0] = load_le32(key) & 0x3ffffffu;
    p->r[1] = (load_le32(key+3) >> 2) & 0x3ffff03u;
    p->r[2] = (load_le32(key+6) >> 4) & 0x3ffc0ffu;
    p->r[3] = (load_le32(key+9) >> 6) & 0x3f03fffu;
    p->r[4] = (load_le32(key+12) >> 8) & 0x00fffffu;
    for (size_t i=0; i<4; ++i) p->pad[i] = load_le32(key+16+4*i);
}
static void poly_block(poly_ctx *p, const uint8_t b[16], uint32_t hibit) {
    uint64_t d[5] = {0};
    uint32_t carry;
    p->h[0] += load_le32(b) & 0x3ffffffu;
    p->h[1] += (load_le32(b+3) >> 2) & 0x3ffffffu;
    p->h[2] += (load_le32(b+6) >> 4) & 0x3ffffffu;
    p->h[3] += (load_le32(b+9) >> 6) & 0x3ffffffu;
    p->h[4] += (load_le32(b+12) >> 8) | hibit;
    for (size_t i=0; i<5; ++i) {
        for (size_t j=0; j<5; ++j) {
            size_t k = (i + 5 - j) % 5;
            d[i] += (uint64_t)p->h[j] * p->r[k] * (j > i ? 5u : 1u);
        }
    }
    for (size_t i=0; i<4; ++i) {
        p->h[i] = (uint32_t)d[i] & 0x3ffffffu;
        d[i+1] += d[i] >> 26;
    }
    p->h[4] = (uint32_t)d[4] & 0x3ffffffu;
    carry = (uint32_t)(d[4] >> 26);
    p->h[0] += carry * 5;
    carry = p->h[0] >> 26;
    p->h[0] &= 0x3ffffffu;
    p->h[1] += carry;
    SECURE_ZERO(d, sizeof(d));
}
static void poly_update(poly_ctx *p, const uint8_t *data, size_t n) {
    while (n) {
        size_t take = 16 - p->used;
        if (take > n) take = n;
        memcpy(p->buffer+p->used, data, take);
        data += take; n -= take; p->used += take;
        if (p->used == 16) {
            poly_block(p, p->buffer, 1u << 24);
            p->used = 0;
        }
    }
}
static void poly_final(poly_ctx *p, uint8_t tag[16]) {
    uint32_t g[5], words[4], carry, mask;
    uint64_t f;
    if (p->used) {
        p->buffer[p->used++] = 1;
        memset(p->buffer+p->used, 0, 16-p->used);
        poly_block(p, p->buffer, 0);
    }
    for (size_t i=1; i<4; ++i) {
        carry=p->h[i]>>26; p->h[i]&=0x3ffffffu; p->h[i+1]+=carry;
    }
    carry=p->h[4]>>26; p->h[4]&=0x3ffffffu; p->h[0]+=carry*5;
    carry=p->h[0]>>26; p->h[0]&=0x3ffffffu; p->h[1]+=carry;
    g[0]=p->h[0]+5; carry=g[0]>>26; g[0]&=0x3ffffffu;
    for (size_t i=1; i<4; ++i) {
        g[i]=p->h[i]+carry; carry=g[i]>>26; g[i]&=0x3ffffffu;
    }
    g[4]=p->h[4]+carry-(1u<<26);
    mask=(g[4]>>31)-1u;
    for (size_t i=0; i<5; ++i) p->h[i]=(p->h[i]&~mask)|(g[i]&mask);
    words[0]=p->h[0]|(p->h[1]<<26);
    words[1]=(p->h[1]>>6)|(p->h[2]<<20);
    words[2]=(p->h[2]>>12)|(p->h[3]<<14);
    words[3]=(p->h[3]>>18)|(p->h[4]<<8);
    f=0;
    for (size_t i=0; i<4; ++i) {
        f=(uint64_t)words[i]+p->pad[i]+(f>>32);
        store_le32(tag+4*i, (uint32_t)f);
    }
    SECURE_ZERO(g, sizeof(g)); SECURE_ZERO(words, sizeof(words));
    SECURE_ZERO(p, sizeof(*p));
}
static void store_le64(uint8_t out[8], uint64_t x) {
    for (size_t i=0; i<8; ++i) out[i]=(uint8_t)(x>>(8*i));
}
static void poly_pad(poly_ctx *p, uint64_t n) {
    static const uint8_t zeros[16]={0};
    if (n%16) poly_update(p, zeros, (size_t)(16-n%16));
}
static void aead_begin(poly_ctx *p, const uint8_t key[32],
                       const uint8_t nonce[12], const uint8_t *aad, size_t n) {
    uint8_t block[64];
    chacha20_block(key, 0, nonce, block);
    poly_init(p, block);
    SECURE_ZERO(block, sizeof(block));
    poly_update(p, aad, n);
    poly_pad(p, n);
}
static void aead_end(poly_ctx *p, uint64_t aadlen, uint64_t clen, uint8_t tag[16]) {
    uint8_t lengths[16];
    poly_pad(p, clen);
    store_le64(lengths, aadlen); store_le64(lengths+8, clen);
    poly_update(p, lengths, sizeof(lengths)); poly_final(p, tag);
}

/* OS adapters. /dev/urandom is the OS CSPRNG, never a userland fallback. */
static int secure_random_bytes(uint8_t *out, size_t n) {
    int fd=open("/dev/urandom", O_RDONLY);
    if (fd<0) return 0;
    while (n) {
        ssize_t got=read(fd, out, n);
        if (got<0 && errno==EINTR) continue;
        if (got<=0) { close(fd); return 0; }
        out+=(size_t)got; n-=(size_t)got;
    }
    return close(fd)==0;
}
static volatile sig_atomic_t password_signal;
static void password_handler(int sig) { password_signal=sig; }
static int read_password(const char *prompt, uint8_t out[JMS_PASSWORD_SIZE], size_t *len) {
    static const int signals[]={SIGINT,SIGTERM,SIGHUP,SIGQUIT,SIGTSTP};
    struct sigaction old[5], action;
    struct termios before, hidden;
    int fd=-1, ok=0, changed=0;
    size_t installed=0, n=0;
    uint8_t c=0;
    *len=0;
    memset(out, 0, JMS_PASSWORD_SIZE);
    fd=open("/dev/tty", O_RDWR);
    if (fd<0 || tcgetattr(fd, &before)!=0) goto done;
    memset(&action, 0, sizeof(action));
    action.sa_handler=password_handler; sigemptyset(&action.sa_mask);
    password_signal=0;
    for (; installed<5; ++installed)
        if (sigaction(signals[installed], &action, &old[installed])!=0) goto done;
    hidden=before;
    hidden.c_lflag &= (tcflag_t)~(ECHO|ECHONL);
    hidden.c_lflag |= ICANON;
    if (tcsetattr(fd, TCSAFLUSH, &hidden)!=0) goto done;
    changed=1;
    if (write(fd, prompt, strlen(prompt))!=(ssize_t)strlen(prompt)) goto done;
    while (!password_signal) {
        ssize_t got=read(fd, &c, 1);
        if (got!=1) break;
        if (c=='\n') { ok=(n>0); break; }
        if (c==0 || n>=JMS_PASSWORD_SIZE-1) break;
        out[n++]=c;
    }
done:
    if (changed) {
        int restored;
        do { restored=tcsetattr(fd, TCSAFLUSH, &before); } while (restored<0 && errno==EINTR);
        if (restored<0) ok=0;
        if (write(fd, "\n", 1)!=1) ok=0;
    }
    for (size_t i=0; i<installed; ++i) (void)sigaction(signals[i], &old[i], NULL);
    if (fd>=0) close(fd);
    SECURE_ZERO(&c, sizeof(c));
    if (password_signal) ok=0;
    if (!ok) SECURE_ZERO(out, JMS_PASSWORD_SIZE);
    else *len=n;
    return ok;
}

/* Serialization: 0 magic JMS3; 4 version=1; 5 KDF=1; 6 AEAD=1; 7 flags=0;
 * 8 salt[16]; 24 nonce[12]; 36 iterations LE32; 40 tag[16]; 56 ciphertext.
 * Bytes 0..39 are AAD. Tag covers AAD, ciphertext and their RFC 8439 lengths. */
static int valid_header(const uint8_t h[JMS_HEADER_SIZE]) {
    uint32_t n=load_le32(h+36);
    return !memcmp(h,"JMS3",4) && h[4]==1 && h[5]==1 && h[6]==1 && h[7]==0
        && n>=JMS_MIN_ITERATIONS && n<=JMS_MAX_ITERATIONS;
}
/* A destination temp is on the same filesystem; link publishes without
 * overwriting even if another process creates the destination meanwhile.
 * Parent directory must be trusted. Crash durability of directory entries is
 * not guaranteed (no directory fsync / macOS F_FULLFSYNC). */
static FILE *output_temp(const char *dest, char **name) {
    size_t n=strlen(dest);
    int fd;
    FILE *f;
    if (n>SIZE_MAX-12) return NULL;
    *name=malloc(n+12);
    if (!*name) return NULL;
    memcpy(*name,dest,n); memcpy(*name+n,".tmp.XXXXXX",12);
    fd=mkstemp(*name); /* mode 0600 */
    if (fd<0) { free(*name); *name=NULL; return NULL; }
    f=fdopen(fd,"w+b");
    if (!f) { close(fd); unlink(*name); free(*name); *name=NULL; }
    return f;
}

/* Shared engine called by the CLI and by the external benchmark harness.
 * Decryption first copies and authenticates ciphertext into an unlinked 0600
 * snapshot. The second pass decrypts that exact snapshot, closing the input
 * modification race of naive two-pass schemes. No plaintext before tag check.
 * This adds disk I/O and up to one ciphertext-sized temporary file. */
static int process_file(int decrypt, const char *src, const char *dest,
                        const uint8_t *password, size_t plen, uint32_t iterations) {
    FILE *in=NULL, *out=NULL, *snapshot=NULL;
    char *tmpname=NULL;
    struct stat st;
    uint8_t h[JMS_HEADER_SIZE]={0}, key[32]={0}, tag[16]={0};
    uint8_t buffer[JMS_BUFFER_SIZE];
    chacha20_ctx_t cipher;
    poly_ctx poly;
    uint64_t total=0;
    size_t n;
    int ok=0, fd=-1;
    const char *error="Falha de entrada/saida";
    memset(&cipher,0,sizeof(cipher)); memset(&poly,0,sizeof(poly));
    if (!plen || plen>=JMS_PASSWORD_SIZE) { error="Senha invalida"; goto done; }
    if (lstat(dest,&st)==0 || errno!=ENOENT) { error="Destino ja existe ou inacessivel"; goto done; }
    fd=open(src,O_RDONLY|O_NONBLOCK);
    if (fd<0) goto done;
    if (fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_size<0) {
        error="Entrada deve ser arquivo regular"; goto done;
    }
    if ((uint64_t)st.st_size > JMS_MAX_BYTES+(decrypt?JMS_HEADER_SIZE:0u)) {
        error="Arquivo excede limite do formato"; goto done;
    }
    in=fdopen(fd,"rb");
    if (!in) goto done;
    fd=-1;
    if (decrypt) {
        if (fread(h,1,sizeof(h),in)!=sizeof(h) || !valid_header(h)) {
            error="Cabecalho invalido ou formato nao suportado"; goto done;
        }
        iterations=load_le32(h+36);
    } else {
        if (iterations<JMS_MIN_ITERATIONS || iterations>JMS_MAX_ITERATIONS) {
            error="Iteracoes fora da politica"; goto done;
        }
        memcpy(h,"JMS3",4); h[4]=h[5]=h[6]=1;
        if (!secure_random_bytes(h+8,28)) { error="Falha no CSPRNG"; goto done; }
        store_le32(h+36,iterations);
    }
    if (!pbkdf2(password,plen,h+8,16,iterations,key)) goto done;
    aead_begin(&poly,key,h+24,h,JMS_AAD_SIZE);
    if (decrypt) {
        /* tmpfile creates an unlinked temporary file; constrain permissions
         * explicitly before storing even ciphertext. */
        snapshot=tmpfile();
        if (!snapshot || fchmod(fileno(snapshot),S_IRUSR|S_IWUSR)!=0) goto done;
    } else {
        out=output_temp(dest,&tmpname);
        if (!out || fwrite(h,1,sizeof(h),out)!=sizeof(h)) goto done;
        chacha20_init(&cipher,key,h+24);
    }
    while ((n=fread(buffer,1,sizeof(buffer),in))!=0) {
        if ((uint64_t)n>JMS_MAX_BYTES-total) { error="Limite ChaCha20 excedido"; goto done; }
        total+=n;
        if (!decrypt) chacha20_xor(&cipher,buffer,n);
        poly_update(&poly,buffer,n);
        if (fwrite(buffer,1,n,decrypt?snapshot:out)!=n) goto done;
    }
    if (ferror(in)) goto done;
    aead_end(&poly,JMS_AAD_SIZE,total,tag);
    if (decrypt) {
        if (!constant_time_equal(tag,h+40,16)) { error="Autenticacao falhou: senha ou arquivo invalido"; goto done; }
        if (fflush(snapshot)!=0 || fseeko(snapshot,0,SEEK_SET)!=0) goto done;
        out=output_temp(dest,&tmpname);
        if (!out) goto done;
        chacha20_init(&cipher,key,h+24);
        while ((n=fread(buffer,1,sizeof(buffer),snapshot))!=0) {
            chacha20_xor(&cipher,buffer,n);
            if (fwrite(buffer,1,n,out)!=n) goto done;
        }
        if (ferror(snapshot)) goto done;
    } else {
        if (fseeko(out,40,SEEK_SET)!=0 || fwrite(tag,1,16,out)!=16) goto done;
    }
    if (fflush(out)!=0 || fsync(fileno(out))!=0) goto done;
    { int rc=fclose(out); out=NULL; if (rc!=0) goto done; }
    if (link(tmpname,dest)!=0) { error="Nao foi possivel publicar destino (nenhum arquivo sobrescrito)"; goto done; }
    ok=1;
done:
    if (fd>=0) close(fd);
    if (in) fclose(in);
    if (out) fclose(out);
    if (snapshot) fclose(snapshot);
    if (tmpname) { unlink(tmpname); free(tmpname); }
    SECURE_ZERO(key,sizeof(key)); SECURE_ZERO(buffer,sizeof(buffer));
    SECURE_ZERO(&cipher,sizeof(cipher)); SECURE_ZERO(&poly,sizeof(poly));
    SECURE_ZERO(tag,sizeof(tag));
    if (!ok) fprintf(stderr,"JMS: %s.\n",error);
    return ok;
}

/* Known-answer vectors: SHA-256 abc; RFC 4231 case 1; PBKDF2-SHA256
 * password/salt c=1; RFC 8439 2.3.2, 2.5.2 and 2.8.2. */
static int equals_hex(const uint8_t *data, size_t n, const char *hex) {
    static const char digits[]="0123456789abcdef";
    if (strlen(hex)!=2*n) return 0;
    for (size_t i=0; i<n; ++i)
        if (digits[data[i]>>4]!=hex[2*i] || digits[data[i]&15]!=hex[2*i+1]) return 0;
    return 1;
}
static int self_test(void) {
    uint8_t out[128], key[32], nonce[12]={0}, tag[16];
    const uint8_t pk[32]={0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,0x01,0x03,0x80,0x8a,
        0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b};
    const uint8_t aad[12]={0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
    const char *plain="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    poly_ctx p;
    chacha20_ctx_t c;
    hmac_sha256_ctx_t hm;
    int ok=1;
    sha256_once((const uint8_t *)"abc",3,out);
    ok &= equals_hex(out,32,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    memset(key,0x0b,20); hmac_sha256_init(&hm,key,20);
    hmac_sha256_update(&hm,(const uint8_t *)"Hi There",8); hmac_sha256_final(&hm,out);
    ok &= equals_hex(out,32,"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    pbkdf2((const uint8_t *)"password",8,(const uint8_t *)"salt",4,1,out);
    ok &= equals_hex(out,32,"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    for (size_t i=0; i<32; ++i) key[i]=(uint8_t)i;
    nonce[3]=9; nonce[7]=0x4a;
    chacha20_block(key,1,nonce,out);
    ok &= equals_hex(out,64,"10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    poly_init(&p,pk); poly_update(&p,(const uint8_t *)"Cryptographic Forum Research Group",34);
    poly_final(&p,tag); ok &= equals_hex(tag,16,"a8061dc1305136c6c22b8baf0c0127a9");
    for (size_t i=0; i<32; ++i) key[i]=(uint8_t)(0x80+i);
    memset(nonce,0,12); nonce[0]=7;
    for (size_t i=4; i<12; ++i) nonce[i]=(uint8_t)(0x40+i-4);
    memcpy(out,plain,114); chacha20_init(&c,key,nonce); chacha20_xor(&c,out,114);
    ok &= equals_hex(out,114,"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63"
        "dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692"
        "ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4"
        "def08e4b7a9de576d26586cec64b6116");
    aead_begin(&p,key,nonce,aad,12); poly_update(&p,out,114); aead_end(&p,12,114,tag);
    ok &= equals_hex(tag,16,"1ae10b594f09e26a7e902ecbd0600691");
    SECURE_ZERO(out,sizeof(out)); SECURE_ZERO(key,sizeof(key)); SECURE_ZERO(&c,sizeof(c));
    puts(ok?"Self-test: OK (6 known-answer checks)":"Self-test: FAILED");
    return ok;
}
static void usage(void) {
    puts("JMS 3.0 — C99/POSIX, PBKDF2-SHA256 + ChaCha20-Poly1305\n"
         "  jms -e -f entrada -o saida.jms\n"
         "  jms -d -f entrada.jms -o saida\n"
         "  jms --self-test | -h | -v\n"
         "Senha: terminal sem eco, 1..255 bytes. Destino deve nao existir.\n"
         "Formato JMS3; arquivos JMS2 nao sao suportados.");
}
int main(int argc, char **argv) {
    const char *src=NULL, *dest=NULL;
    uint8_t password[JMS_PASSWORD_SIZE]={0}, confirm[JMS_PASSWORD_SIZE]={0};
    size_t plen=0, clen=0;
    int mode=-1, ok=0;
    if (argc==2 && !strcmp(argv[1],"--self-test")) return self_test()?0:1;
    if (argc==2 && !strcmp(argv[1],"-v")) { puts("JMS 3.0 / format JMS3 v1"); return 0; }
    if (argc==2 && !strcmp(argv[1],"-h")) { usage(); return 0; }
    for (int i=1; i<argc; ++i) {
        if (!strcmp(argv[i],"-e") && mode<0) mode=0;
        else if (!strcmp(argv[i],"-d") && mode<0) mode=1;
        else if (!strcmp(argv[i],"-f") && !src && i+1<argc) src=argv[++i];
        else if (!strcmp(argv[i],"-o") && !dest && i+1<argc) dest=argv[++i];
        else { usage(); return 2; }
    }
    if (mode<0 || !src || !dest) { usage(); return 2; }
    if (!read_password("Senha: ",password,&plen)) goto done;
    if (!mode) {
        if (!read_password("Confirme: ",confirm,&clen)) goto done;
        if (plen!=clen || !constant_time_equal(password,confirm,JMS_PASSWORD_SIZE)) {
            fputs("Senhas diferentes.\n",stderr); goto done;
        }
    }
    SECURE_ZERO(confirm,sizeof(confirm));
    ok=process_file(mode,src,dest,password,plen,JMS_DEFAULT_ITERATIONS);
done:
    SECURE_ZERO(password,sizeof(password)); SECURE_ZERO(confirm,sizeof(confirm));
    if (!ok) { fputs("Operacao nao concluida.\n",stderr); return 1; }
    puts("Operacao concluida.");
    return 0;
}
