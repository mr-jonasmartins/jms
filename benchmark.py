#!/usr/bin/env python3
"""Reproducible POSIX benchmark. Standard Python library + C compiler.
Creates a fresh results directory; never benchmarks the user's real files.
"""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
PASSWORD = b"JMS-public-benchmark-only-2026"


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def capture(cmd):
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout.strip()
    except OSError as e:
        return str(e)


def measured(cmd, logfile, timeout=1800):
    # Small C parent measures one child, avoiding Python's pre-exec RSS peak.
    collector = Path(logfile).parent / "measure"
    measurement = Path(logfile).parent / "measurement.json"
    with open(logfile, "wb") as log:
        p = subprocess.Popen([str(collector), str(measurement), *map(str,cmd)],
                             stdout=log, stderr=log, start_new_session=True)
        try:
            p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            import signal
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
            raise RuntimeError("Timeout: " + str(cmd))
    if p.returncode:
        raise RuntimeError(f"Exit {p.returncode}: {cmd}\n{Path(logfile).read_text(errors='replace')}")
    return json.loads(measurement.read_text())


def call(driver, *args, good=True):
    p = subprocess.run([str(driver), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if (p.returncode == 0) != good:
        raise RuntimeError(f"Validation failed {args}: {p.returncode}\n{p.stderr.decode(errors='replace')}")
    return p.stdout.decode().strip()


def validate(driver, work):
    """Cheap mandatory correctness gates before collecting any measurements."""
    checks = []
    call(driver, "self-test")
    checks.append("6 known-answer checks embedded in jms.c")
    for iterations in (1, 2, 4096):
        expected = hashlib.pbkdf2_hmac("sha256", PASSWORD, bytes(16), iterations, 32).hex()
        assert call(driver, "kdf", iterations) == expected, "PBKDF2 differential mismatch"
    checks.append("PBKDF2 vs hashlib at 1, 2 and 4096 iterations")
    src, enc, dst = (work / x for x in ("test.in", "test.jms", "test.out"))
    rng = random.Random(8439)
    for n in (0, 1, 15, 16, 17, 63, 64, 65, 4096, 65535, 65536, 65537, 1048576):
        src.write_bytes(bytes(rng.getrandbits(8) for _ in range(n)))
        call(driver, "enc", src, enc, 100000)
        assert enc.stat().st_size == n + 56
        call(driver, "dec", enc, dst, 100000)
        assert digest(src) == digest(dst)
        assert dst.stat().st_mode & 0o777 == 0o600
        enc.unlink(); dst.unlink()
    checks.append("13 round trips: 0..1 MiB, block and I/O buffer boundaries, mode 0600, 56-byte overhead")
    src.write_bytes(bytes(range(128)))
    call(driver, "enc", src, enc, 100000)
    original = enc.read_bytes()
    call(driver, "wrong", enc, dst, 100000, good=False)
    assert not dst.exists()
    checks.append("Wrong password rejected without output")
    # All serialized header fields plus ciphertext, truncation and appended data.
    bad = work / "bad.jms"
    cases = []
    for offset in (0, 4, 5, 6, 7, 8, 24, 36, 40, 55, 56, len(original)-1):
        b = bytearray(original); b[offset] ^= 1; cases.append(bytes(b))
    cases += [original[:n] for n in (0, 4, 39, 55, 56, len(original)-1)]
    cases += [original + b"x"]
    for iterations in (0, 99999, 5000001, 4294967295):
        b = bytearray(original)
        b[36:40] = iterations.to_bytes(4, "little")
        cases.append(bytes(b))
    for b in cases:
        bad.write_bytes(b)
        call(driver, "dec", bad, dst, 100000, good=False)
        assert not dst.exists(), "Rejected input created plaintext"
    checks.append(f"{len(cases)} corruption/truncation/append cases rejected without output")
    dst.write_bytes(b"DO NOT OVERWRITE")
    call(driver, "enc", src, dst, 100000, good=False)
    assert dst.read_bytes() == b"DO NOT OVERWRITE"
    dst.unlink(); dst.symlink_to(src)
    call(driver, "enc", src, dst, 100000, good=False)
    assert src.read_bytes() == bytes(range(128))
    dst.unlink()
    checks.append("Existing destination and destination symlink preserved")
    call(driver, "enc", src, src, 100000, good=False)
    assert src.read_bytes() == bytes(range(128))
    fresh = work / "fresh.jms"
    call(driver, "enc", src, fresh, 100000)
    assert fresh.read_bytes()[8:36] != original[8:36], "Repeated salt/nonce"
    fresh.unlink()
    checks.append("Same input/output rejected; fresh salt/nonce on repeated encryption")
    for p in (src, enc, bad):
        p.unlink()
    return checks


def percentile(values, q):
    a = sorted(values)
    pos = (len(a)-1) * q
    i = int(pos)
    return a[i] + (a[min(i+1,len(a)-1)] - a[i]) * (pos-i)


def summarize(rows):
    groups = {}
    for r in rows:
        groups.setdefault((r["operation"], r["bytes"], r["iterations"]), []).append(r)
    result = []
    for (op, n, it), group in sorted(groups.items()):
        ts = [r["seconds"] for r in group]
        median = statistics.median(ts)
        result.append(dict(operation=op, bytes=n, iterations=it, samples=len(ts),
            median_seconds=median, q1_seconds=percentile(ts,.25), q3_seconds=percentile(ts,.75),
            min_seconds=min(ts), max_seconds=max(ts), mean_seconds=statistics.mean(ts),
            sd_seconds=statistics.stdev(ts) if len(ts)>1 else 0,
            median_mib_s=n/1048576/median if n else None,
            median_peak_rss_mib=statistics.median(r["peak_rss_mib"] for r in group)))
    return result


def csv_write(path, rows):
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def report(out, meta, summary, checks):
    quick = meta["profile"] == "quick"
    lines = ["# Relatório de benchmark JMS 3.0", "",
        "**" + ("ENSAIO RÁPIDO: serve para verificar o pipeline; não constitui a avaliação final." if quick else
        "Resultados medidos nesta máquina. Revisar o texto e as limitações antes de incorporar ao artigo.") + "**", "",
        "## Ambiente e protocolo", "",
        f"- Data UTC: {meta['date_utc']}",
        f"- Sistema: {meta['platform']}; arquitetura: {meta['machine']}",
        f"- CPU: {meta['cpu']}; RAM: {meta['ram_bytes']} bytes",
        f"- Compilador: {meta['compiler_version'].splitlines()[0]}",
        f"- Flags: `{' '.join(meta['flags'])}`",
        f"- SHA-256 do fonte: `{meta['source_sha256']}`",
        f"- Executável de produção: {meta['binary_bytes']} bytes; fonte: {meta['source_bytes']} bytes / {meta['source_lines']} linhas físicas",
        f"- Repetições medidas por condição: {meta['repeats']}; aquecimentos: {meta['warmups']}; semente da ordem: {meta['seed']}",
        f"- Dependências dinâmicas do binário: ver `metadata.json`.", "",
        "Tempo medido por relógio monotônico em um pequeno coletor C, de fork até waitpid do processo filho. "
        "Inclui criação do processo e inicialização/finalização. O coletor evita herdar o pico de RSS do Python na medição. Entrada interativa de senha foi excluída: "
        "o harness fornece uma senha pública fixa à mesma função utilizada pelo CLI. Não usar o harness em arquivos reais. "
        "Cada amostra usa um processo novo. RSS é o pico desse processo de teste, não uma medição isolada do CLI.", "",
        "Os arquivos sintéticos usam blocos pseudoaleatórios determinísticos repetidos, sem compressão explícita. "
        "São criados fora da janela medida. Há aquecimento e cache do sistema operacional não é esvaziado; "
        "o ensaio caracteriza condições com cache aquecido/misto, não desempenho de armazenamento a frio. "
        "A ordem das condições é embaralhada a cada repetição. Cada descriptografia é verificada por SHA-256 fora da janela medida.", "",
        "## Validação prévia", "", *["- " + x for x in checks], "",
        "## Resultados", "",
        "| Operação | Bytes | Iterações KDF | n | Mediana (s) | Q1–Q3 (s) | MiB/s | Pico RSS mediano (MiB) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for r in summary:
        throughput = '—' if r['median_mib_s'] is None else f"{r['median_mib_s']:.2f}"
        lines.append(f"| {r['operation']} | {r['bytes']} | {r['iterations']} | {r['samples']} | "
            f"{r['median_seconds']:.6f} | {r['q1_seconds']:.6f}–{r['q3_seconds']:.6f} | {throughput} | {r['median_peak_rss_mib']:.2f} |")
    lines += ["", "Operações: `enc`/`dec` incluem PBKDF2, AEAD, I/O e `fsync` do arquivo final temporário; "
        "`dec` inclui criação e releitura da cópia cifrada autenticada. `copy` é somente referência de I/O, sem segurança criptográfica. "
        "`kdf` mede derivação de uma chave de 32 bytes. `aead` e `sodium` medem registros de 1 MiB em memória, "
        "sem KDF nem arquivos, incluindo cópia do buffer e inicialização/finalização do processo. "
        "Seu throughput não equivale ao throughput da ferramenta de arquivos.", "",
        "## Texto-base para a seção experimental", "",
        f"O JMS foi avaliado em {meta['platform']} ({meta['machine']}), utilizando {meta['repeats']} repetições "
        f"por condição e {meta['warmups']} execução(ões) de aquecimento. Foram registrados tempo de parede, "
        "tempo de CPU e pico de memória residente por processo. A Tabela de Resultados apresenta medianas "
        "e quartis; as amostras completas estão disponíveis em raw.csv. As operações de arquivos empregaram "
        "PBKDF2-HMAC-SHA256 com 600.000 iterações e ChaCha20-Poly1305. Os testes de adulteração e de "
        "recuperação do conteúdo foram concluídos antes da coleta. Esses resultados caracterizam o artefato "
        "no ambiente registrado e não demonstram, por si, segurança criptográfica ou superioridade geral.", "",
        "## Interpretação e limitações", "",
        "- Examinar o efeito do custo fixo da KDF sobre arquivos pequenos; não subtrair medianas de experimentos independentes para estimar tempo puro da cifra.",
        "- O pico RSS não inclui integralmente cache do SO nem contabiliza toda a memória compartilhada de bibliotecas.",
        "- O tamanho do executável depende de símbolos, compilador e ligação dinâmica; não representa toda a base confiável.",
        "- 600.000 iterações é parâmetro provisório do projeto; esta avaliação de latência não mede resistência a ataques de senha.",
        "- Não foram controlados núcleos de desempenho/eficiência, frequência, pressão térmica ou atividades do SO. Registrar condições de energia e repetir sessões.",
        "- fsync faz parte do protocolo, mas não equivale a garantia de persistência física no macOS; não foi usado F_FULLFSYNC nem fsync do diretório.",
        "- Arquivo único e menor tamanho não demonstram auditabilidade ou segurança; auditoria independente, fuzzing e avaliação de canais laterais continuam pendentes.",
        "- A preservação da zeroização sob otimização exige inspeção de assembly; não foi inferida a partir destes tempos.",
        "- Comparações ponta a ponta com age/GnuPG e com wrappers equivalentes de outras bibliotecas continuam em aberto."]
    if meta['sodium_enabled']:
        lines += ["- libsodium foi medida apenas no microbenchmark AEAD, com os mesmos tamanhos de registro, AAD e condições. "
                  "Uma comparação diferencial ocorreu fora da janela medida. Versão e ligação constam dos metadados."]
    else:
        lines += ["- Nenhuma biblioteca externa foi medida nesta execução. Para comparação AEAD opcional, consultar --sodium-prefix no roteiro."]
    if quick:
        lines += ["- Por ser ensaio rápido, o parágrafo acima é modelo metodológico; executar o perfil article antes de utilizá-lo como resultado científico."]
    lines += ["", "## Referências de especificação", "",
              "- RFC 8439: https://www.rfc-editor.org/rfc/rfc8439", "- RFC 8018: https://www.rfc-editor.org/rfc/rfc8018", ""]
    (out / "relatorio.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["quick", "article"], default="quick")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--cc", default="cc", help="One compiler executable, not a shell command")
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--seed", type=int, default=20260926)
    parser.add_argument("--large", action="store_true", help="Add 1 GiB file; reserve at least 5 GiB")
    parser.add_argument("--sodium-prefix", type=Path, help="Optional libsodium prefix, e.g. brew --prefix libsodium")
    a = parser.parse_args()
    if platform.system() not in ("Darwin", "Linux"):
        parser.error("macOS or Linux required")
    repeats = a.repeats if a.repeats is not None else (2 if a.profile=="quick" else 7)
    if repeats < 1:
        parser.error("repeats must be positive")
    out = (a.out or ROOT / ("resultados-" + time.strftime("%Y%m%d-%H%M%S"))).resolve()
    out.mkdir(parents=True, exist_ok=False)
    flags = ["-std=c99", "-O2", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
    production, driver = out / "jms", out / "bench_driver"
    builds = [[a.cc, *flags, str(ROOT/"jms.c"), "-o", str(production)],
              [a.cc, *flags, str(ROOT/"bench_driver.c"), "-o", str(driver)],
              [a.cc, *flags, str(ROOT/"measure.c"), "-o", str(out/"measure")]]
    if a.sodium_prefix:
        prefix = a.sodium_prefix.resolve()
        builds[1] += ["-DJMS_HAVE_SODIUM", "-I"+str(prefix/"include"), "-L"+str(prefix/"lib"),
                      "-Wl,-rpath,"+str(prefix/"lib"), "-lsodium"]
    for cmd in builds:
        p = subprocess.run(cmd, capture_output=True, text=True)
        with open(out/"build.log", "a") as log:
            log.write(json.dumps(cmd)+"\n"+p.stdout+p.stderr)
        if p.returncode:
            raise RuntimeError("Compilation failed: see build.log")
    sysname = platform.system()
    ram = (int(capture(["sysctl", "-n", "hw.memsize"])) if sysname=="Darwin"
           else os.sysconf("SC_PAGE_SIZE")*os.sysconf("SC_PHYS_PAGES"))
    cpu = capture(["sysctl", "-n", "machdep.cpu.brand_string"]) if sysname=="Darwin" else platform.processor()
    if sysname=="Linux" and Path("/proc/cpuinfo").exists():
        cpu=next((l.split(":",1)[1].strip() for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("model name")),cpu)
    metadata = dict(date_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        profile=a.profile, platform=platform.platform(), machine=platform.machine(), cpu=cpu,
        ram_bytes=ram, python=sys.version, compiler_version=capture([a.cc,"--version"]),
        flags=flags, builds=builds, source_sha256=digest(ROOT/"jms.c"),
        harness_sha256=digest(ROOT/"bench_driver.c"), collector_sha256=digest(ROOT/"measure.c"), script_sha256=digest(Path(__file__)),
        source_bytes=(ROOT/"jms.c").stat().st_size, source_lines=len((ROOT/"jms.c").read_text().splitlines()),
        binary_bytes=production.stat().st_size, binary_sha256=digest(production),
        driver_bytes=driver.stat().st_size, repeats=repeats, warmups=1, seed=a.seed,
        sodium_enabled=bool(a.sodium_prefix), disk=shutil.disk_usage(out)._asdict(),
        dependencies=capture(["otool","-L",str(production)] if sysname=="Darwin" else ["ldd",str(production)]),
        driver_dependencies=capture(["otool","-L",str(driver)] if sysname=="Darwin" else ["ldd",str(driver)]))
    if a.sodium_prefix:
        header=(a.sodium_prefix/"include"/"sodium"/"version.h").read_text()
        metadata["sodium_version_header"]=header
    (out/"metadata.json").write_text(json.dumps(metadata,indent=2,ensure_ascii=False))
    sizes = [1024,1048576] if a.profile=="quick" else [1024,1048576,10485760,104857600]
    if a.large:
        sizes.append(1073741824)
    # Inputs, encrypted fixtures, snapshot and decrypted output can coexist.
    needed=2*sum(sizes)+2*max(sizes)+512*1048576
    if shutil.disk_usage(out).free < needed:
        raise RuntimeError(f"Need at least {needed/1073741824:.2f} GiB free")
    rows=[]
    with tempfile.TemporaryDirectory(prefix="jms-work-",dir=out) as td:
        work=Path(td)
        print("Validando corretude e rejeição de arquivos inválidos...", flush=True)
        checks=validate(driver,work)
        if a.sodium_prefix:
            call(driver,"sodium-check")
            checks.append("libsodium AEAD ciphertext/tag vs JMS, 1 MiB, outside timing")
        (out/"validation.json").write_text(json.dumps(checks,indent=2))
        rng=random.Random(a.seed)
        block=bytes(rng.getrandbits(8) for _ in range(1048576))
        inputs={}
        for n in sizes:
            src=work/f"data-{n}.bin"; enc=work/f"data-{n}.jms"
            with src.open("wb") as f:
                remaining=n
                while remaining:
                    take=min(remaining,len(block)); f.write(block[:take]); remaining-=take
            call(driver,"enc",src,enc,600000)
            inputs[n]=(src,enc,digest(src))
        (out/"inputs.json").write_text(json.dumps({str(n): v[2] for n,v in inputs.items()},indent=2))
        jobs=[(op,n,600000 if op!="copy" else 0) for n in sizes for op in ("enc","dec","copy")]
        jobs += [("kdf",0,it) for it in ((600000,) if a.profile=="quick" else (100000,300000,600000,1000000))]
        records=2 if a.profile=="quick" else 64
        jobs += [("aead",records*1048576,0)]
        if a.sodium_prefix:
            jobs += [("sodium",records*1048576,0)]
        for rep in range(repeats+1):
            order=list(jobs); rng.shuffle(order)
            for index,(op,n,it) in enumerate(order):
                dest=work/"output.tmp"
                if op in ("enc","dec","copy"):
                    src=inputs[n][1 if op=="dec" else 0]
                    cmd=[driver,op,src,dest,it] if op!="copy" else [driver,op,src,dest]
                elif op=="kdf":
                    cmd=[driver,op,it]
                else:
                    cmd=[driver,op,records]
                print(f"{'warmup' if rep==0 else str(rep)+'/'+str(repeats)} {op} bytes={n} iterations={it}",flush=True)
                result=measured(cmd,out/"last-run.log")
                if op in ("dec","copy") and digest(dest)!=inputs[n][2]:
                    raise RuntimeError("Output digest mismatch")
                if op=="enc":
                    recovered=work/"verified.tmp"
                    call(driver,"dec",dest,recovered,600000)
                    if digest(recovered)!=inputs[n][2]:
                        raise RuntimeError("Encryption round-trip mismatch")
                    recovered.unlink()
                if dest.exists():
                    dest.unlink()
                if rep:
                    rows.append(dict(repetition=rep, order=index, operation=op, bytes=n, iterations=it,**result))
                    csv_write(out/"raw.csv",rows)
        summary=summarize(rows)
        csv_write(out/"summary.csv",summary)
        report(out,metadata,summary,checks)
    print(f"Concluído: {out / 'relatorio.md'}",flush=True)


if __name__=="__main__":
    try:
        main()
    except (OSError,RuntimeError,AssertionError) as e:
        print(f"ERRO: {e}",file=sys.stderr)
        sys.exit(1)
