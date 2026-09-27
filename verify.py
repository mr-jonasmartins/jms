#!/usr/bin/env python3
"""Additional verification: sanitizers, terminal and optional reference oracle."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import random
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
from benchmark import ROOT, validate, capture


def terminal_case(binary, args, passwords, cancel=False):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(str(binary), [str(binary), *map(str,args)])
    transcript = b""
    deadline = time.monotonic()+60
    index = 0
    status = None
    try:
        while time.monotonic()<deadline:
            ready,_,_=select.select([fd],[],[],.02)
            if ready:
                try:
                    chunk=os.read(fd,4096)
                except OSError as e:
                    if e.errno==errno.EIO:
                        break
                    raise
                transcript += chunk
                prompt = b"Senha: " if index==0 else b"Confirme: "
                if index<len(passwords) and prompt in transcript:
                    assert not termios.tcgetattr(fd)[3] & termios.ECHO, "Password echo enabled"
                    if cancel:
                        os.kill(pid,signal.SIGINT)
                    else:
                        os.write(fd,passwords[index]+b"\n")
                    index+=1
            done, status0=os.waitpid(pid,os.WNOHANG)
            if done:
                status=status0
                break
        if status is None:
            done,status0=os.waitpid(pid,os.WNOHANG)
            if not done:
                os.kill(pid,signal.SIGKILL)
                _,status0=os.waitpid(pid,0)
                raise RuntimeError("Terminal timeout")
            status=status0
        for pw in passwords:
            if pw:
                assert pw not in transcript, "Password echoed"
        assert termios.tcgetattr(fd)[3] & termios.ECHO, "Terminal echo not restored"
        return os.waitstatus_to_exitcode(status),transcript.decode(errors="replace")
    finally:
        os.close(fd)


def reference_tests(work, cc):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    wrapper = work/"oracle.c"
    wrapper.write_text('''#define main jms_cli_main
#include "jms.c"
#undef main
void check_poly(const uint8_t *key,const uint8_t *m,size_t n,uint8_t *tag) {
    poly_ctx p; poly_init(&p,key);
    for(size_t i=0;i<n;) { size_t k=n-i>7?7:n-i; poly_update(&p,m+i,k); i+=k; }
    poly_final(&p,tag);
}
void check_aead(const uint8_t *key,const uint8_t *nonce,const uint8_t *aad,size_t alen,
                uint8_t *data,size_t n,uint8_t *tag) {
    chacha20_ctx_t c; poly_ctx p;
    chacha20_init(&c,key,nonce);
    for(size_t i=0;i<n;) { size_t k=n-i>23?23:n-i; chacha20_xor(&c,data+i,k); i+=k; }
    aead_begin(&p,key,nonce,aad,alen);
    for(size_t i=0;i<n;) { size_t k=n-i>31?31:n-i; poly_update(&p,data+i,k); i+=k; }
    aead_end(&p,alen,n,tag);
}
void check_kdf(const uint8_t *pw,size_t pn,const uint8_t *salt,size_t sn,uint32_t it,uint8_t *out) {
    pbkdf2(pw,pn,salt,sn,it,out);
}
''')
    libpath=work/"oracle.so"
    subprocess.run([cc,"-std=c99","-O2","-fPIC","-dynamiclib" if sys.platform=="darwin" else "-shared",
                    "-I",str(ROOT),str(wrapper),"-o",str(libpath)],check=True)
    lib=ctypes.CDLL(str(libpath))
    ptr=ctypes.c_void_p; size=ctypes.c_size_t
    lib.check_poly.argtypes=[ptr,ptr,size,ptr]
    lib.check_aead.argtypes=[ptr,ptr,ptr,size,ptr,size,ptr]
    lib.check_kdf.argtypes=[ptr,size,ptr,size,ctypes.c_uint32,ptr]
    rng=random.Random(80188439)
    rb=lambda n: bytes(rng.getrandbits(8) for _ in range(n))
    lengths=list(range(80))+[127,128,129,255,256,257,4095,4096,4097,65535,65536,65537]
    for n in lengths:
        key,nonce,msg,aad=rb(32),rb(12),rb(n),rb(n%43)
        tag=ctypes.create_string_buffer(16)
        lib.check_poly(key,msg,n,tag)
        assert tag.raw==Poly1305.generate_tag(key,msg),f"Poly1305 n={n}"
        data=ctypes.create_string_buffer(msg,len(msg)+1)
        lib.check_aead(key,nonce,aad,len(aad),data,n,tag)
        assert data.raw[:n]+tag.raw==ChaCha20Poly1305(key).encrypt(nonce,msg,aad),f"AEAD n={n}"
    edge_count=0
    for key in (bytes(32), bytes([255])*32, bytes([1])*32):
        for n in (0,1,15,16,17,32,64,1024):
            msg=bytes([255])*n
            tag=ctypes.create_string_buffer(16)
            lib.check_poly(key,msg,n,tag)
            assert tag.raw==Poly1305.generate_tag(key,msg)
            edge_count+=1
    # Long HMAC keys exercise the SHA-256 key compression path.
    for pn in (0,1,63,64,65,127,255):
        pw,salt=rb(pn),rb(19)
        out=ctypes.create_string_buffer(32)
        lib.check_kdf(pw,pn,salt,len(salt),17,out)
        assert out.raw==hashlib.pbkdf2_hmac("sha256",pw,salt,17,32)
    return [f"{len(lengths)} Poly1305 and {len(lengths)} AEAD differential cases, fragmented updates",
            f"{edge_count} Poly1305 extreme-key/message cases",
            "7 PBKDF2 cases with password lengths 0..255 vs hashlib"]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cc",default="cc")
    p.add_argument("--reference",action="store_true",help="Require optional Python cryptography package")
    p.add_argument("--out",type=Path,default=ROOT/"verification.json")
    a=p.parse_args()
    os.environ.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
    checks=[]
    with tempfile.TemporaryDirectory(prefix="jms-verify-") as td:
        work=Path(td)
        for opt in ("-O0","-O2","-O3","-O3 -flto"):
            binary=work/"jms"
            subprocess.run([a.cc,"-std=c99",*opt.split(),"-Wall","-Wextra","-Wpedantic","-Werror",
                            str(ROOT/"jms.c"),"-o",str(binary)],check=True)
            subprocess.run([str(binary),"--self-test"],check=True)
            checks.append("Known-answer vectors "+opt)
        driver=work/"driver-sanitized"
        subprocess.run([a.cc,"-std=c99","-O1","-g","-fsanitize=address,undefined","-fno-omit-frame-pointer",
                        str(ROOT/"bench_driver.c"),"-o",str(driver)],check=True)
        # GCC PIE + ASan can fail to map shadow memory in some restricted Linux
        # runners. Do not hide that failure; rerun with a suitable compiler/environment.
        checks.extend(validate(driver,work))
        checks.append("ASan + UBSan on correctness/negative-file suite")
        src,enc,dst=(work/x for x in ("terminal.in","terminal.jms","terminal.out"))
        src.write_bytes(b"terminal test\x00\xff")
        pw=b"public-terminal-test-password"
        rc,_=terminal_case(binary,["-e","-f",src,"-o",enc],[pw,pw])
        assert rc==0
        rc,_=terminal_case(binary,["-d","-f",enc,"-o",dst],[pw])
        assert rc==0 and src.read_bytes()==dst.read_bytes()
        for passwords in ([b""],[pw,b"different"],[b"x"*256]):
            rejected=work/"rejected"
            rc,_=terminal_case(binary,["-e","-f",src,"-o",rejected],passwords)
            assert rc!=0 and not rejected.exists()
        rc,_=terminal_case(binary,["-e","-f",src,"-o",work/"cancelled"],[pw],cancel=True)
        assert rc!=0
        checks.append("PTY: encrypt/decrypt, no echo, restore, empty/oversized/mismatched passwords and SIGINT")
        if a.reference:
            checks.extend(reference_tests(work,a.cc))
        else:
            checks.append("SKIPPED optional reference oracle (use --reference)")
    result=dict(date_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                platform=sys.platform,compiler=capture([a.cc,"--version"]),checks=checks,
                sanitizer_environment={k:os.environ.get(k) for k in ("ASAN_OPTIONS","UBSAN_OPTIONS","LSAN_OPTIONS")},
                note="Passing tests is not a security audit; no timing/zeroization proof.")
    a.out.write_text(json.dumps(result,indent=2,ensure_ascii=False))
    print("Verification OK:",a.out)


if __name__=="__main__":
    main()
