# JMS — Just Message Security

JMS é um utilitário experimental de criptografia autenticada de arquivos, escrito em **C99** e mantido em um único arquivo-fonte: [`jms.c`](jms.c).

O projeto investiga as decisões de implementação e os custos computacionais de uma ferramenta de arquivos sem dependências criptográficas de terceiros no executável de produção. O pacote inclui instrumentos de validação, benchmarks e os resultados de três sessões realizadas em um Apple M1.

Repositório: <https://github.com/mr-jonasmartins/jms>

## Escopo

- Cifragem autenticada: **ChaCha20-Poly1305, variante IETF**.
- Derivação de chave: **PBKDF2-HMAC-SHA256**, com chave de 32 bytes e 600.000 iterações por padrão.
- Salt aleatório de 16 bytes e nonce aleatório de 12 bytes por cifragem.
- Senha solicitada no terminal, sem eco; confirmação durante a cifragem.
- Autenticação dos metadados e verificação antes da produção de texto claro.
- Processamento de arquivos em blocos e recusa de sobrescrita do destino.
- Plataformas-alvo: **macOS e Linux**, por meio de interfaces POSIX. Esta versão não implementa suporte a Windows.

**Estado do projeto:** artefato de pesquisa. Os testes documentam o comportamento nos casos avaliados; o projeto não possui auditoria independente nem prova formal de segurança. Código compacto e ausência de bibliotecas criptográficas externas não demonstram superioridade de segurança.

O executável depende dos serviços e da biblioteca do sistema operacional. Python, libsodium e Python `cryptography` pertencem ao ambiente experimental, conforme o ensaio escolhido; não são dependências do programa JMS.

## Arquivos do projeto

| Arquivo ou diretório | Finalidade |
|---|---|
| [`jms.c`](jms.c) | Utilitário completo e testes internos de resposta conhecida |
| [`bench_driver.c`](bench_driver.c) | Driver que chama as rotinas do JMS para os experimentos |
| [`measure.c`](measure.c) | Coletor de tempo de execução e recursos do processo |
| [`benchmark.py`](benchmark.py) | Compilação, validação, coleta e relatório por sessão |
| [`verify.py`](verify.py) | Verificação adicional, incluindo sanitizadores e referência opcional |
| [`ROTEIRO.md`](ROTEIRO.md) | Procedimento detalhado de uso, validação e benchmark |
| [`VALIDACAO.md`](VALIDACAO.md) | Evidências e limites da validação de desenvolvimento |
| [`Analise-benchmark-JMS-M1.md`](Analise-benchmark-JMS-M1.md) | Consolidação das três sessões experimentais |
| [`resultados/`](resultados/) | Dados brutos, metadados e relatórios das sessões utilizadas no artigo |

A restrição de arquivo único aplica-se ao programa JMS. Os demais fontes e scripts são instrumentos de pesquisa.

## Requisitos

Para compilar e usar o JMS:

- macOS ou Linux;
- compilador C com suporte a C99;
- terminal interativo para a senha;
- diretório de saída confiável e sistema de arquivos com suporte a hard links.

Para o laboratório:

- Python 3.9 ou posterior;
- libsodium, somente para a comparação AEAD;
- pacote Python `cryptography`, somente para `verify.py --reference`.

No macOS, os comandos abaixo devem ser executados em um terminal nativo da arquitetura do equipamento. No M1, `uname -m` deve indicar `arm64`.

## Compilar e verificar o programa

Execute na raiz do projeto:

```bash
cc -std=c99 -O2 -Wall -Wextra -Wpedantic -Werror jms.c -o jms
./jms --self-test
./jms -v
```

Resposta esperada do teste interno:

```text
Self-test: OK (6 known-answer checks)
```

## Cifrar e decifrar

Exemplo com um arquivo descartável:

```bash
printf 'Exemplo de uso do JMS\n' > exemplo.txt
./jms -e -f exemplo.txt -o exemplo.jms
./jms -d -f exemplo.jms -o recuperado.txt
cmp exemplo.txt recuperado.txt
```

A senha é digitada no terminal. Durante a digitação, os caracteres não aparecem na tela. A cifragem solicita confirmação. Na decifragem, informe a mesma senha.

O comando `cmp` termina sem mensagem e com código zero quando os arquivos são iguais. Os caminhos de saída devem ser novos: o programa recusa sobrescrever arquivos existentes. A senha não é fornecida por argumentos, variável de ambiente ou entrada padrão redirecionada.

Para consultar a ajuda:

```bash
./jms -h
```

O formato atual é **JMS3** e contém um cabeçalho de 56 bytes. Ele é incompatível com JMS2. Arquivos antigos exigem a implementação correspondente para recuperação antes de uma eventual migração.

## Validação adicional

```bash
python3 verify.py --out verificacao-local.json
```

Para incluir a referência Python `cryptography`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography
python verify.py --reference --out verificacao-local-referencia.json
python -m pip freeze > versoes-verificacao.txt
```

É possível continuar com a `.venv` ativa ao executar o benchmark. O script compila seus próprios executáveis com `-O2`; os testes com sanitizadores pertencem à verificação separada.

## Benchmark rápido

```bash
python3 benchmark.py --profile quick --out execucoes-locais/rapido
```

Esse perfil verifica o procedimento com arquivos de 1 KiB e 1 MiB e duas repetições medidas por condição. Ele não corresponde ao conjunto de resultados utilizado no artigo.

Cada diretório indicado por `--out` precisa ser novo. A pasta será criada pelo script. Se a compilação falhar, consulte `build.log` dentro dela.

## Repetir o protocolo do artigo no macOS

O perfil `article` utiliza arquivos de 1 KiB, 1 MiB, 10 MiB e 100 MiB, uma execução de aquecimento descartada e sete repetições medidas por condição. A comparação com libsodium resulta em 18 condições por sessão.

Com libsodium instalada via Homebrew:

```bash
brew install libsodium

caffeinate -i python3 benchmark.py --profile article --repeats 7 \
  --seed 20260926 --sodium-prefix "$(brew --prefix libsodium)" \
  --out execucoes-locais/sessao1

caffeinate -i python3 benchmark.py --profile article --repeats 7 \
  --seed 20260927 --sodium-prefix "$(brew --prefix libsodium)" \
  --out execucoes-locais/sessao2

caffeinate -i python3 benchmark.py --profile article --repeats 7 \
  --seed 20260928 --sodium-prefix "$(brew --prefix libsodium)" \
  --out execucoes-locais/sessao3
```

Os comandos criam novas execuções, separadas dos registros históricos em `resultados/`. O `caffeinate` é específico do macOS. No Linux, execute `python3 benchmark.py` diretamente e informe em `--sodium-prefix` o prefixo da instalação da biblioteca, contendo `include/sodium.h` e `lib/libsodium`.

Para executar o perfil sem comparação externa, omita `--sodium-prefix`. Isso produz um conjunto diferente de condições e não reproduz integralmente a avaliação comparativa do artigo.

Mantenha as condições de energia registradas, a tampa aberta no MacBook e espaço livre de pelo menos 1 GiB para o perfil padrão. Consulte o [roteiro](ROTEIRO.md) para o procedimento completo. Reproduzir o protocolo com outras versões de compilador ou biblioteca não garante os mesmos tempos; as diferenças devem ser registradas.

O driver utiliza dados sintéticos e uma senha pública de teste. **Não utilize `bench_driver` para proteger documentos.**

## Dados e resultados

As três sessões históricas devem permanecer organizadas nestes caminhos:

- [`resultados/resultados-m1-sodium/`](resultados/resultados-m1-sodium/)
- [`resultados/resultados-m1-sodium-sessao2/`](resultados/resultados-m1-sodium-sessao2/)
- [`resultados/resultados-m1-sodium-sessao3/`](resultados/resultados-m1-sodium-sessao3/)

Cada sessão contém `raw.csv`, `summary.csv`, `metadata.json`, `inputs.json`, `validation.json`, `relatorio.md` e `build.log`. `measurement.json` e `last-run.log`, quando preservados, são registros auxiliares da última execução.

A coleta no Apple M1, com 8 GiB de RAM, reuniu **378 medições**, distribuídas em três sessões no mesmo dia. Os valores abaixo são consolidados pela mediana das três medianas de sessão:

| Ensaio | Tempo consolidado | Vazão consolidada |
|---|---:|---:|
| Cifrar 100 MiB, incluindo KDF e I/O | 1,148387 s | 87,08 MiB/s |
| Decifrar 100 MiB, incluindo KDF e I/O | 1,173694 s | 85,20 MiB/s |
| PBKDF2-HMAC-SHA256, 600.000 iterações | 0,609529 s | Não se aplica |
| AEAD JMS: 64 registros de 1 MiB em memória | 0,303068 s | 211,17 MiB/s |
| AEAD libsodium: 64 registros de 1 MiB em memória | 0,169851 s | 376,80 MiB/s |

A mediana das razões de vazão libsodium/JMS calculadas por sessão foi **1,780**. Essa comparação cobre cifragem AEAD em memória, excluindo KDF e I/O de arquivos. Não é uma comparação entre ferramentas completas de proteção de arquivos.

O executável JMS medido ocupou 52.304 bytes e apresentou ligação dinâmica apenas com `libSystem.B.dylib`. Seu tamanho varia conforme ambiente e compilação.

O script produz estatísticas por sessão. A consolidação entre sessões e suas limitações estão documentadas em [Analise-benchmark-JMS-M1.md](Analise-benchmark-JMS-M1.md).

## Limitações e rastreabilidade

Os resultados caracterizam um único equipamento e três sessões de curto prazo. Não houve controle de frequência, temperatura, afinidade de núcleos ou esvaziamento do cache do sistema. A semente alterou tanto a ordem de execução quanto o conteúdo dos arquivos sintéticos.

A memória medida é o pico de RSS do driver, não toda a memória e o armazenamento usados pelo sistema. A comparação com libsodium não demonstra superioridade geral de uma ferramenta nem isola a causa da diferença de desempenho.

SHA-256 de `jms.c` utilizado na avaliação:

```text
22c73a2dc15f39239d455c08401e2481dc82fe3d29a3028d7847a1d13fe39c0f
```

Antes de associar novos resultados a esta avaliação, confira a versão dos fontes e os metadados. O commit ou tag correspondente ao artefato experimental deve ser registrado no artigo após a publicação. A denominação JMS 3.0 não substitui esse identificador.

## Licença

A licença de distribuição ainda será definida pelo autor. Esta documentação não atribui automaticamente uma licença ao código. Quando definida, inclua o arquivo `LICENSE` e atualize esta seção.
