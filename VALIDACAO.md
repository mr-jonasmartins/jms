# Validação realizada antes da entrega

Data: 26/09/2026. Ambiente: Linux x86_64 de desenvolvimento; GCC 13.3.0. **Não são resultados do MacBook M1.**

| Verificação | Resultado |
|---|---|
| C99, `-Wall -Wextra -Wpedantic -Werror` | Compilação sem avisos |
| Vetores conhecidos com `-O0`, `-O2`, `-O3`, `-O3 -flto` | Passaram |
| 6 verificações internas: SHA-256, HMAC, PBKDF2, ChaCha20, Poly1305, AEAD | Passaram |
| PBKDF2 contra hashlib, 1/2/4096 iterações | Passou |
| 13 arquivos de 0 bytes a 1 MiB, incluindo fronteiras de blocos/buffer | Recuperação byte a byte correta |
| Senha incorreta | Rejeitada, sem criar destino |
| 23 casos de corrupção, truncamento, extensão e KDF fora da política | Rejeitados, sem criar destino |
| Destino preexistente, link simbólico e entrada=saída | Preservados/rejeitados |
| Salt/nonce novos em duas cifragens consecutivas | Diferentes |
| 92 casos Poly1305 contra Python cryptography | Passaram |
| 92 casos AEAD contra Python cryptography, atualizações fragmentadas | Passaram |
| 24 casos adicionais Poly1305, chaves zero/um/0xff e mensagem 0xff | Passaram |
| 7 casos PBKDF2, senhas de 0 a 255 bytes, contra hashlib | Passaram |
| ASan + UBSan na suíte de corretude/arquivos inválidos | Sem erros reportados |
| Terminal via PTY: cifrar, decifrar, ausência de eco e restauração | Passou |
| Senhas vazia, longa e confirmação diferente; Ctrl+C no prompt | Rejeitadas/interrompida, com restauração de eco |
| Pipeline de benchmark rápido e relatório/CSVs/metadados | Executado com sucesso |

A execução de LeakSanitizer foi bloqueada pelo ambiente de desenvolvimento (restrição de inspeção de processos/ptrace). A suíte foi repetida com `ASAN_OPTIONS=detect_leaks=0`; AddressSanitizer e UndefinedBehaviorSanitizer permaneceram habilitados. A execução final também utilizou `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. Portanto **não há resultado de detecção de vazamentos de memória** nesta entrega.

A comparação opcional de benchmark com libsodium exige seus cabeçalhos de desenvolvimento e deve ser executada no Mac conforme o roteiro. Essa integração opcional não foi executada neste ambiente; os testes diferenciais independentes de corretude usaram Python cryptography. O benchmark padrão não depende de libsodium.

Ainda não realizados: validação nativa em macOS/ARM64; benchmarks finais no M1; revisão independente; fuzzing; análise estática completa; ensaios de canais laterais; inspeção sistemática do assembly para zeroização; testes de falta de energia e todas as possíveis falhas de I/O; comparação ponta a ponta com ferramentas externas.

O protótipo não deve ser descrito no artigo como “auditado”, “com segurança comprovada” ou “mais seguro por ter menos código”. Os testes sustentam apenas as observações delimitadas acima. Os resultados experimentais do artigo permanecem em aberto até a coleta no equipamento-alvo.
