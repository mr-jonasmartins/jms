/* Experimental harness, not part of the standalone JMS tool.
 * Password below is PUBLIC and only for disposable synthetic test files.
 * Uses the exact process_file() implementation from jms.c.
 */
#define main jms_cli_main
#include "jms.c"
#undef main
#ifdef JMS_HAVE_SODIUM
#include <sodium.h>
#endif
#include <time.h>
static const uint8_t test_password[]="JMS-public-benchmark-only-2026";
static uint64_t number(const char *s) {
    char *end;
    unsigned long long n;
    errno=0; n=strtoull(s,&end,10);
    if (errno || !*s || *end || *s=='-') exit(2);
    return (uint64_t)n;
}
static int copy_file(const char *src, const char *dest) {
    uint8_t b[JMS_BUFFER_SIZE];
    FILE *in=fopen(src,"rb"), *out=NULL;
    char *tmp=NULL;
    size_t n;
    int ok=0;
    if (!in) return 0;
    out=output_temp(dest,&tmp);
    if (!out) goto done;
    while ((n=fread(b,1,sizeof(b),in))) if (fwrite(b,1,n,out)!=n) goto done;
    if (ferror(in) || fflush(out) || fsync(fileno(out))) goto done;
    { int rc=fclose(out); out=NULL; if (rc) goto done; }
    ok=link(tmp,dest)==0;
done:
    fclose(in); if(out) fclose(out);
    if(tmp) { unlink(tmp); free(tmp); }
    return ok;
}
/* Fixed 1 MiB records; both engines include the same buffer initialization,
 * nonce increment and memory copy, exclude KDF/file I/O, use a 40-byte AAD.
 * Per-record AEAD length is different from single-message file encryption. */
static int aead_benchmark(int sodium_mode, uint64_t records) {
    const size_t n=1048576;
    uint8_t key[32]={0}, nonce[12]={0}, aad[40]={0}, tag[16];
    uint8_t *source=calloc(n,1), *data=malloc(n);
    chacha20_ctx_t c;
    poly_ctx p;
    unsigned checksum=0;
    if (!source || !data) { free(source); free(data); return 0; }
#ifndef JMS_HAVE_SODIUM
    if (sodium_mode) { free(source); free(data); return 0; }
#else
    if (sodium_init()<0) { free(source); free(data); return 0; }
    /* Before timing comparisons, validate libsodium versus JMS once. */
    if (sodium_mode==2) {
        uint8_t expected[16];
        memcpy(data,source,n);
        chacha20_init(&c,key,nonce); chacha20_xor(&c,data,n);
        aead_begin(&p,key,nonce,aad,40); poly_update(&p,data,n); aead_end(&p,40,n,expected);
        if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(source,tag,NULL,
                source,n,aad,40,NULL,nonce,key)!=0 || memcmp(source,data,n) || memcmp(tag,expected,16)) {
            free(source); free(data); return 0;
        }
        free(source); free(data); return 1;
    }
#endif
    for (uint64_t i=0; i<records; ++i) {
        store_le64(nonce,i+1); memcpy(data,source,n);
        if (sodium_mode) {
#ifdef JMS_HAVE_SODIUM
            if (crypto_aead_chacha20poly1305_ietf_encrypt_detached(data,tag,NULL,
                    data,n,aad,40,NULL,nonce,key)!=0) { free(source); free(data); return 0; }
#endif
        } else {
            chacha20_init(&c,key,nonce); chacha20_xor(&c,data,n);
            aead_begin(&p,key,nonce,aad,40); poly_update(&p,data,n); aead_end(&p,40,n,tag);
        }
        checksum+=tag[0];
    }
    printf("checksum=%u\n",checksum);
    SECURE_ZERO(&c,sizeof(c)); SECURE_ZERO(&p,sizeof(p));
    SECURE_ZERO(data,n); free(source); free(data); return 1;
}
int main(int argc, char **argv) {
    uint8_t key[32], salt[16]={0};
    uint64_t iterations;
    if (argc==2 && !strcmp(argv[1],"self-test")) return self_test()?0:1;
    if (argc==3 && !strcmp(argv[1],"kdf")) {
        iterations=number(argv[2]);
        if (!iterations || iterations>JMS_MAX_ITERATIONS) return 2;
        pbkdf2(test_password,sizeof(test_password)-1,salt,16,(uint32_t)iterations,key);
        for(size_t i=0;i<32;++i) printf("%02x",key[i]);
        puts(""); SECURE_ZERO(key,sizeof(key)); return 0;
    }
    if (argc==2 && !strcmp(argv[1],"sodium-check")) return aead_benchmark(2,0)?0:1;
    if (argc==3 && (!strcmp(argv[1],"aead") || !strcmp(argv[1],"sodium")))
        return aead_benchmark(!strcmp(argv[1],"sodium"),number(argv[2]))?0:1;
    if (argc==4 && !strcmp(argv[1],"copy")) return copy_file(argv[2],argv[3])?0:1;
    if (argc!=5) return 2;
    iterations=number(argv[4]);
    if (iterations>UINT32_MAX) return 2;
    if (!strcmp(argv[1],"enc") || !strcmp(argv[1],"dec") || !strcmp(argv[1],"wrong")) {
        const uint8_t *pw=test_password;
        size_t plen=sizeof(test_password)-1;
        if (!strcmp(argv[1],"wrong")) { pw=(const uint8_t *)"wrong"; plen=5; }
        return process_file(strcmp(argv[1],"enc")!=0,argv[2],argv[3],pw,plen,(uint32_t)iterations)?0:1;
    }
    return 2;
}
