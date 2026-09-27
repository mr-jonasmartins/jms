# Relatório de benchmark JMS 3.0

**Resultados medidos nesta máquina. Revisar o texto e as limitações antes de incorporar ao artigo.**

## Ambiente e protocolo

- Data UTC: 2026-09-26T22:22:55Z
- Sistema: macOS-27.0-arm64-arm-64bit; arquitetura: arm64
- CPU: Apple M1; RAM: 8589934592 bytes
- Compilador: Apple clang version 21.0.0 (clang-2100.3.34.2)
- Flags: `-std=c99 -O2 -Wall -Wextra -Wpedantic -Werror`
- SHA-256 do fonte: `22c73a2dc15f39239d455c08401e2481dc82fe3d29a3028d7847a1d13fe39c0f`
- Executável de produção: 52304 bytes; fonte: 29367 bytes / 786 linhas físicas
- Repetições medidas por condição: 7; aquecimentos: 1; semente da ordem: 20260928
- Dependências dinâmicas do binário: ver `metadata.json`.

Tempo medido por relógio monotônico em um pequeno coletor C, de fork até waitpid do processo filho. Inclui criação do processo e inicialização/finalização. O coletor evita herdar o pico de RSS do Python na medição. Entrada interativa de senha foi excluída: o harness fornece uma senha pública fixa à mesma função utilizada pelo CLI. Não usar o harness em arquivos reais. Cada amostra usa um processo novo. RSS é o pico desse processo de teste, não uma medição isolada do CLI.

Os arquivos sintéticos usam blocos pseudoaleatórios determinísticos repetidos, sem compressão explícita. São criados fora da janela medida. Há aquecimento e cache do sistema operacional não é esvaziado; o ensaio caracteriza condições com cache aquecido/misto, não desempenho de armazenamento a frio. A ordem das condições é embaralhada a cada repetição. Cada descriptografia é verificada por SHA-256 fora da janela medida.

## Validação prévia

- 6 known-answer checks embedded in jms.c
- PBKDF2 vs hashlib at 1, 2 and 4096 iterations
- 13 round trips: 0..1 MiB, block and I/O buffer boundaries, mode 0600, 56-byte overhead
- Wrong password rejected without output
- 23 corruption/truncation/append cases rejected without output
- Existing destination and destination symlink preserved
- Same input/output rejected; fresh salt/nonce on repeated encryption
- libsodium AEAD ciphertext/tag vs JMS, 1 MiB, outside timing

## Resultados

| Operação | Bytes | Iterações KDF | n | Mediana (s) | Q1–Q3 (s) | MiB/s | Pico RSS mediano (MiB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| aead | 67108864 | 0 | 7 | 0.303068 | 0.302612–0.304405 | 211.17 | 3.67 |
| copy | 1024 | 0 | 7 | 0.006363 | 0.005614–0.006434 | 0.15 | 1.56 |
| copy | 1048576 | 0 | 7 | 0.007786 | 0.006723–0.008412 | 128.44 | 1.59 |
| copy | 10485760 | 0 | 7 | 0.012695 | 0.011467–0.014679 | 787.71 | 1.59 |
| copy | 104857600 | 0 | 7 | 0.039846 | 0.039016–0.043056 | 2509.66 | 1.59 |
| dec | 1024 | 600000 | 7 | 0.611226 | 0.610710–0.614304 | 0.00 | 1.62 |
| dec | 1048576 | 600000 | 7 | 0.620220 | 0.618802–0.621550 | 1.61 | 1.62 |
| dec | 10485760 | 600000 | 7 | 0.672924 | 0.671023–0.674804 | 14.86 | 1.62 |
| dec | 104857600 | 600000 | 7 | 1.173694 | 1.169293–1.182249 | 85.20 | 1.62 |
| enc | 1024 | 600000 | 7 | 0.613303 | 0.610893–0.614281 | 0.00 | 1.62 |
| enc | 1048576 | 600000 | 7 | 0.617262 | 0.616265–0.618599 | 1.62 | 1.62 |
| enc | 10485760 | 600000 | 7 | 0.668142 | 0.666606–0.669401 | 14.97 | 1.62 |
| enc | 104857600 | 600000 | 7 | 1.148387 | 1.146775–1.148951 | 87.08 | 1.62 |
| kdf | 0 | 100000 | 7 | 0.106149 | 0.105132–0.106806 | — | 1.55 |
| kdf | 0 | 300000 | 7 | 0.308542 | 0.307313–0.309993 | — | 1.55 |
| kdf | 0 | 600000 | 7 | 0.609529 | 0.608205–0.609837 | — | 1.55 |
| kdf | 0 | 1000000 | 7 | 1.011197 | 1.010525–1.012989 | — | 1.55 |
| sodium | 67108864 | 0 | 7 | 0.170216 | 0.169821–0.171304 | 375.99 | 3.72 |

Operações: `enc`/`dec` incluem PBKDF2, AEAD, I/O e `fsync` do arquivo final temporário; `dec` inclui criação e releitura da cópia cifrada autenticada. `copy` é somente referência de I/O, sem segurança criptográfica. `kdf` mede derivação de uma chave de 32 bytes. `aead` e `sodium` medem registros de 1 MiB em memória, sem KDF nem arquivos, incluindo cópia do buffer e inicialização/finalização do processo. Seu throughput não equivale ao throughput da ferramenta de arquivos.

## Texto-base para a seção experimental

O JMS foi avaliado em macOS-27.0-arm64-arm-64bit (arm64), utilizando 7 repetições por condição e 1 execução(ões) de aquecimento. Foram registrados tempo de parede, tempo de CPU e pico de memória residente por processo. A Tabela de Resultados apresenta medianas e quartis; as amostras completas estão disponíveis em raw.csv. As operações de arquivos empregaram PBKDF2-HMAC-SHA256 com 600.000 iterações e ChaCha20-Poly1305. Os testes de adulteração e de recuperação do conteúdo foram concluídos antes da coleta. Esses resultados caracterizam o artefato no ambiente registrado e não demonstram, por si, segurança criptográfica ou superioridade geral.

## Interpretação e limitações

- Examinar o efeito do custo fixo da KDF sobre arquivos pequenos; não subtrair medianas de experimentos independentes para estimar tempo puro da cifra.
- O pico RSS não inclui integralmente cache do SO nem contabiliza toda a memória compartilhada de bibliotecas.
- O tamanho do executável depende de símbolos, compilador e ligação dinâmica; não representa toda a base confiável.
- 600.000 iterações é parâmetro provisório do projeto; esta avaliação de latência não mede resistência a ataques de senha.
- Não foram controlados núcleos de desempenho/eficiência, frequência, pressão térmica ou atividades do SO. Registrar condições de energia e repetir sessões.
- fsync faz parte do protocolo, mas não equivale a garantia de persistência física no macOS; não foi usado F_FULLFSYNC nem fsync do diretório.
- Arquivo único e menor tamanho não demonstram auditabilidade ou segurança; auditoria independente, fuzzing e avaliação de canais laterais continuam pendentes.
- A preservação da zeroização sob otimização exige inspeção de assembly; não foi inferida a partir destes tempos.
- Comparações ponta a ponta com age/GnuPG e com wrappers equivalentes de outras bibliotecas continuam em aberto.
- libsodium foi medida apenas no microbenchmark AEAD, com os mesmos tamanhos de registro, AAD e condições. Uma comparação diferencial ocorreu fora da janela medida. Versão e ligação constam dos metadados.

## Referências de especificação

- RFC 8439: https://www.rfc-editor.org/rfc/rfc8439
- RFC 8018: https://www.rfc-editor.org/rfc/rfc8018
