#ifdef _WIN32
#define _CRT_RAND_S
#include <windows.h>
#define SECURE_ZERO(ptr, size) SecureZeroMemory((ptr), (size))
#else
#include <stddef.h>
#include <stdint.h>
/* Implementação universal segura para macOS e Linux */
static void secure_memzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}
#define SECURE_ZERO(ptr, size) secure_memzero((ptr), (size))
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * JMS (Just Message Security) v2.0 - Criptografia de arquivos em C.
 *
 * Interface de linha de comando (mantida simples):
 * Criptografar:   jms -f <arquivo_entrada> -c <chave> -o <arquivo_saida>
 * Descriptografar: jms -f <arquivo_entrada> -d <chave> -o <arquivo_saida>
 *
 * Estrategia criptografica adotada:
 * 1) Derivacao de chave a partir da senha (KDF iterativo com SHA-256 + salt).
 * 2) Cifragem de dados com ChaCha20.
 * 3) Autenticacao com HMAC-SHA256 sobre cabecalho (sem MAC) + ciphertext.
 *
 * Propriedades:
 * - Chave/senha errada causa falha de autenticacao.
 * - Arquivo adulterado causa falha de autenticacao.
 * - Arquivo invalido (cabecalho incorreto) e rejeitado antes da decriptacao.
 */

#define JMS_VERSION 1u
#define JMS_SALT_SIZE 16u
#define JMS_NONCE_SIZE 12u
#define JMS_KEY_SIZE 32u
#define JMS_MAC_SIZE 32u
#define JMS_BUFFER_SIZE 4096u
#define JMS_KDF_ITERATIONS 200000u

/*
 * Layout do cabecalho JMS2 (em bytes):
 * magic[4]   : assinatura fixa "JMS2"
 * version[1] : versao do formato
 * salt[16]   : salt aleatorio para derivacao de chave
 * nonce[12]  : nonce do ChaCha20
 * iter[4]    : iteracoes da KDF (little-endian)
 * mac[32]    : HMAC-SHA256 do cabecalho (sem mac) + ciphertext
 */

typedef struct {
    uint8_t magic[4];
    uint8_t version;
    uint8_t salt[JMS_SALT_SIZE];
    uint8_t nonce[JMS_NONCE_SIZE];
    uint32_t iterations;
    uint8_t mac[JMS_MAC_SIZE];
} jms_header_t;

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
    uint32_t counter;
    uint8_t keystream[64];
    size_t keystream_offset;
} chacha20_ctx_t;

static const uint8_t JMS_MAGIC[4] = {'J', 'M', 'S', '2'};
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

/*
 * Gera bytes aleatorios a partir de /dev/urandom.
 * Retorna 1 em sucesso e 0 em falha.
 */

static int secure_random_bytes(uint8_t *out, size_t len) {
#ifdef _WIN32
    size_t produced = 0;
    while (produced < len) {
        unsigned int value = 0;
        if (rand_s(&value) != 0) {
            return 0;
        }

        for (size_t i = 0; i < sizeof(value) && produced < len; ++i) {
            out[produced++] = (uint8_t)((value >> (i * 8u)) & 0xFFu);
        }
    }
    return 1;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        return 0;
    }

    if (fread(out, 1, len, f) != len) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return 1;
#endif
}

/*
 * Processa um bloco de 512 bits do SHA-256.
 * Funcao central de compressao do algoritmo.
 */

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
            chacha20_block(ctx->key, ctx->counter++, ctx->nonce, ctx->keystream);
            ctx->keystream_offset = 0u;
        }
        data[i] ^= ctx->keystream[ctx->keystream_offset++];
    }
}

/*
 * Deriva chave mestra de 32 bytes a partir de senha + salt.
 * Implementacao iterativa para elevar custo de brute force.
 */

static void derive_master_key(const char *password, const uint8_t salt[JMS_SALT_SIZE], uint32_t iterations, uint8_t out[32]) {
    const size_t pass_len = strlen(password);
    uint8_t digest[32];
    uint8_t iter_le[4];
    sha256_ctx_t ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)password, pass_len);
    sha256_update(&ctx, salt, JMS_SALT_SIZE);
    sha256_final(&ctx, digest);

    for (uint32_t i = 1; i < iterations; ++i) {
        store_le32(iter_le, i);
        sha256_init(&ctx);
        sha256_update(&ctx, digest, sizeof(digest));
        sha256_update(&ctx, (const uint8_t *)password, pass_len);
        sha256_update(&ctx, salt, JMS_SALT_SIZE);
        sha256_update(&ctx, iter_le, sizeof(iter_le));
        sha256_final(&ctx, digest);
    }

    memcpy(out, digest, 32);
}

/*
 * Deriva subchaves especificas por rotulo a partir da chave mestra.
 * Ex.: "JMS-ENC" para cifra e "JMS-MAC" para autenticacao.
 */

static void derive_subkey(const uint8_t master[32], const char *label, uint8_t out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, master, 32);
    sha256_update(&ctx, (const uint8_t *)label, strlen(label));
    sha256_final(&ctx, out);
}

/* Utilitarios de leitura/escrita de inteiro little-endian em arquivo. */

static int write_u32_le_file(FILE *f, uint32_t v) {
    uint8_t b[4];
    store_le32(b, v);
    return fwrite(b, 1, sizeof(b), f) == sizeof(b);
}

static int read_u32_le_file(FILE *f, uint32_t *v) {
    uint8_t b[4];
    if (fread(b, 1, sizeof(b), f) != sizeof(b)) {
        return 0;
    }
    *v = load_le32(b);
    return 1;
}

/* Serializa/deserializa cabecalho JMS2. */

static int write_header(FILE *f, const jms_header_t *h) {
    if (fwrite(h->magic, 1, sizeof(h->magic), f) != sizeof(h->magic)) return 0;
    if (fwrite(&h->version, 1, 1, f) != 1) return 0;
    if (fwrite(h->salt, 1, JMS_SALT_SIZE, f) != JMS_SALT_SIZE) return 0;
    if (fwrite(h->nonce, 1, JMS_NONCE_SIZE, f) != JMS_NONCE_SIZE) return 0;
    if (!write_u32_le_file(f, h->iterations)) return 0;
    if (fwrite(h->mac, 1, JMS_MAC_SIZE, f) != JMS_MAC_SIZE) return 0;
    return 1;
}

static int read_header(FILE *f, jms_header_t *h) {
    if (fread(h->magic, 1, sizeof(h->magic), f) != sizeof(h->magic)) return 0;
    if (fread(&h->version, 1, 1, f) != 1) return 0;
    if (fread(h->salt, 1, JMS_SALT_SIZE, f) != JMS_SALT_SIZE) return 0;
    if (fread(h->nonce, 1, JMS_NONCE_SIZE, f) != JMS_NONCE_SIZE) return 0;
    if (!read_u32_le_file(f, &h->iterations)) return 0;
    if (fread(h->mac, 1, JMS_MAC_SIZE, f) != JMS_MAC_SIZE) return 0;
    return 1;
}

/*
 * Alimenta no HMAC apenas os campos autenticados do cabecalho,
 * excluindo o proprio campo mac.
 */

static void hmac_update_header_fields(hmac_sha256_ctx_t *hmac, const jms_header_t *h) {
    hmac_sha256_update(hmac, h->magic, sizeof(h->magic));
    hmac_sha256_update(hmac, &h->version, 1);
    hmac_sha256_update(hmac, h->salt, JMS_SALT_SIZE);
    hmac_sha256_update(hmac, h->nonce, JMS_NONCE_SIZE);

    uint8_t iter[4];
    store_le32(iter, h->iterations);
    hmac_sha256_update(hmac, iter, sizeof(iter));
}

/* Tamanho fixo do cabecalho JMS2 em bytes. */

static long header_size_bytes(void) {
    return 4L + 1L + (long)JMS_SALT_SIZE + (long)JMS_NONCE_SIZE + 4L + (long)JMS_MAC_SIZE;
}

/*
 * Fluxo de criptografia com limpeza segura de memoria.
 */

static int encrypt_file(FILE *in, FILE *out, const char *password) {
    jms_header_t header;
    uint8_t master_key[32] = {0};
    uint8_t enc_key[32] = {0};
    uint8_t mac_key[32] = {0};
    hmac_sha256_ctx_t hmac;
    chacha20_ctx_t chacha;
    uint8_t buffer[JMS_BUFFER_SIZE];
    int status_ret = 0; /* 0 indica erro por defeito */

    memcpy(header.magic, JMS_MAGIC, sizeof(header.magic));
    header.version = (uint8_t)JMS_VERSION;
    header.iterations = JMS_KDF_ITERATIONS;
    memset(header.mac, 0, JMS_MAC_SIZE);

    if (!secure_random_bytes(header.salt, JMS_SALT_SIZE) || !secure_random_bytes(header.nonce, JMS_NONCE_SIZE)) {
        printf("Erro ao gerar aleatoriedade segura.\n");
        goto cleanup;
    }

    derive_master_key(password, header.salt, header.iterations, master_key);
    derive_subkey(master_key, "JMS-ENC", enc_key);
    derive_subkey(master_key, "JMS-MAC", mac_key);

    if (!write_header(out, &header)) {
        printf("Erro ao escrever arquivo de saida.\n");
        goto cleanup;
    }

    hmac_sha256_init(&hmac, mac_key, sizeof(mac_key));
    hmac_update_header_fields(&hmac, &header);

    chacha20_init(&chacha, enc_key, header.nonce);

    while (!feof(in)) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (ferror(in)) {
            printf("Erro ao ler arquivo de entrada.\n");
            goto cleanup;
        }
        if (n == 0) {
            break;
        }

        chacha20_xor(&chacha, buffer, n);
        hmac_sha256_update(&hmac, buffer, n);

        if (fwrite(buffer, 1, n, out) != n) {
            printf("Erro ao escrever arquivo de saida.\n");
            goto cleanup;
        }
    }

    hmac_sha256_final(&hmac, header.mac);

    if (fseek(out, 0L, SEEK_SET) != 0) {
        printf("Erro ao finalizar arquivo de saida.\n");
        goto cleanup;
    }

    if (!write_header(out, &header)) {
        printf("Erro ao finalizar arquivo de saida.\n");
        goto cleanup;
    }

    status_ret = 1; /* Sucesso */

cleanup:
    /* Limpeza de memoria garantida pelo SECURE_ZERO independentemente do resultado */
    SECURE_ZERO(master_key, sizeof(master_key));
    SECURE_ZERO(enc_key, sizeof(enc_key));
    SECURE_ZERO(mac_key, sizeof(mac_key));
    SECURE_ZERO(&chacha, sizeof(chacha));
    SECURE_ZERO(&hmac, sizeof(hmac));
    SECURE_ZERO(buffer, sizeof(buffer));

    return status_ret;
}

/*
 * Fluxo de descriptografia com limpeza segura de memoria.
 */

static int decrypt_file(FILE *in, FILE *out, const char *password) {
    jms_header_t header;
    uint8_t master_key[32] = {0};
    uint8_t enc_key[32] = {0};
    uint8_t mac_key[32] = {0};
    uint8_t computed_mac[32] = {0};
    hmac_sha256_ctx_t hmac;
    chacha20_ctx_t chacha;
    uint8_t buffer[JMS_BUFFER_SIZE];
    long data_start;
    int status_ret = 0; /* 0 indica erro por defeito */

    if (!read_header(in, &header)) {
        printf("Arquivo invalido ou corrompido.\n");
        goto cleanup;
    }

    if (memcmp(header.magic, JMS_MAGIC, sizeof(header.magic)) != 0) {
        printf("Formato de arquivo invalido.\n");
        goto cleanup;
    }

    if (header.version != JMS_VERSION) {
        printf("Versao de arquivo nao suportada.\n");
        goto cleanup;
    }

    if (header.iterations < 1000u || header.iterations > 10000000u) {
        printf("Cabecalho invalido.\n");
        goto cleanup;
    }

    derive_master_key(password, header.salt, header.iterations, master_key);
    derive_subkey(master_key, "JMS-ENC", enc_key);
    derive_subkey(master_key, "JMS-MAC", mac_key);

    hmac_sha256_init(&hmac, mac_key, sizeof(mac_key));
    hmac_update_header_fields(&hmac, &header);

    while (!feof(in)) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (ferror(in)) {
            printf("Erro ao ler arquivo de entrada.\n");
            goto cleanup;
        }
        if (n == 0) {
            break;
        }
        hmac_sha256_update(&hmac, buffer, n);
    }

    hmac_sha256_final(&hmac, computed_mac);

    if (!constant_time_equal(computed_mac, header.mac, JMS_MAC_SIZE)) {
        printf("Chave incorreta ou arquivo adulterado.\n");
        goto cleanup;
    }

    data_start = header_size_bytes();
    if (fseek(in, data_start, SEEK_SET) != 0) {
        printf("Erro ao reposicionar leitura.\n");
        goto cleanup;
    }

    chacha20_init(&chacha, enc_key, header.nonce);

    while (!feof(in)) {
        size_t n = fread(buffer, 1, sizeof(buffer), in);
        if (ferror(in)) {
            printf("Erro ao ler arquivo de entrada.\n");
            goto cleanup;
        }
        if (n == 0) {
            break;
        }

        chacha20_xor(&chacha, buffer, n);
        if (fwrite(buffer, 1, n, out) != n) {
            printf("Erro ao escrever arquivo de saida.\n");
            goto cleanup;
        }
    }

    status_ret = 1; /* Sucesso */

cleanup:
    /* Limpeza de memoria garantida pelo SECURE_ZERO independentemente do resultado */
    SECURE_ZERO(master_key, sizeof(master_key));
    SECURE_ZERO(enc_key, sizeof(enc_key));
    SECURE_ZERO(mac_key, sizeof(mac_key));
    SECURE_ZERO(computed_mac, sizeof(computed_mac));
    SECURE_ZERO(&chacha, sizeof(chacha));
    SECURE_ZERO(&hmac, sizeof(hmac));
    SECURE_ZERO(buffer, sizeof(buffer));

    return status_ret;
}

/*
 * main:
 * - Faz parse dos argumentos.
 * - Abre arquivos de entrada/saida.
 * - Executa criptografia (-c) ou descriptografia (-d).
 * - Em falha, remove arquivo de saida parcial.
 */

int main(int argc, char *argv[]) {

    char *input = NULL;
    char *output = NULL;
    char *key_str = NULL;

    int mode_encrypt = 0;
    int mode_decrypt = 0;
    int exec_status = 1;

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            input = argv[++i];
        }
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            key_str = argv[++i];
            mode_encrypt = 1;
        }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            key_str = argv[++i];
            mode_decrypt = 1;
        }
    }

    if (!input || !output || !key_str || (mode_encrypt == mode_decrypt)) {
        printf("Uso:\n");
        printf("  Criptografar:   jms -f entrada -c chave -o saida\n");
        printf("  Descriptografar: jms -f entrada -d chave -o saida\n");
        return 1;
    }

    FILE *in = fopen(input, "rb");

    if (!in) {
        printf("Erro ao abrir arquivos.\n");
        /* O key_str contem a password da linha de comandos, vamos limpar */
        if (key_str) SECURE_ZERO(key_str, strlen(key_str));
        return 1;
    }

    if (mode_encrypt) {
        FILE *out = fopen(output, "wb");
        if (!out) {
            fclose(in);
            printf("Erro ao abrir arquivos.\n");
            if (key_str) SECURE_ZERO(key_str, strlen(key_str));
            return 1;
        }

        if (!encrypt_file(in, out, key_str)) {
            fclose(in);
            fclose(out);
            remove(output);
            if (key_str) SECURE_ZERO(key_str, strlen(key_str));
            return 1;
        }

        fclose(in);
        fclose(out);
        printf("Arquivo criptografado com sucesso!\n");
        if (key_str) SECURE_ZERO(key_str, strlen(key_str));
        return 0;
    }

    FILE *out = fopen(output, "wb");
    if (!out) {
        fclose(in);
        printf("Erro ao abrir arquivos.\n");
        if (key_str) SECURE_ZERO(key_str, strlen(key_str));
        return 1;
    }

    if (!decrypt_file(in, out, key_str)) {
        fclose(in);
        fclose(out);
        remove(output);
        if (key_str) SECURE_ZERO(key_str, strlen(key_str));
        return 1;
    }

    fclose(in);
    fclose(out);

    printf("Arquivo descriptografado com sucesso!\n");
    if (key_str) SECURE_ZERO(key_str, strlen(key_str));

    return 0;
}
