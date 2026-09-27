# JMS 3.0 — roteiro de implementação, validação e benchmark

## 1. Decisão de escopo: macOS e Linux

Windows não é necessário para a pergunta experimental. Esta versão concentra a implementação em macOS e Linux, com núcleo C99 e adaptadores POSIX. O suporte a Windows fica como trabalho futuro. A retirada dessas rotinas reduz a quantidade de caminhos de plataforma a revisar, mas não prova melhoria de segurança ou desempenho.

O ambiente principal do estudo será o seu **MacBook M1, 8 GB de RAM e unidade de 256 GB**. Registre modelo exato, versão do macOS, espaço livre, compilador e modo de energia. O tamanho nominal do armazenamento não é RAM nem espaço livre; a medição registrará a capacidade disponível no volume de teste.

Não afirmar “portabilidade multiplataforma demonstrada” apenas por compilar no Mac. O pacote foi verificado em um ambiente Linux de desenvolvimento; os experimentos no M1 ainda serão executados por você.

## 2. Arquivos

| Arquivo | Função |
|---|---|
| `jms.c` | Utilitário completo, compilável isoladamente, sem bibliotecas criptográficas de terceiros |
| `benchmark.py` | Compila, valida, aquece, mede, agrega e produz relatório em português |
| `bench_driver.c` | Acesso experimental às mesmas funções do JMS; senha pública fixa para dados sintéticos |
| `measure.c` | Coletor POSIX de tempo e recursos de um único processo filho |
| `verify.py` | Verificação adicional com otimizações, sanitizadores, terminal e referência opcional |
| `VALIDACAO.md` | Evidências e limites da validação feita antes da entrega |
| `ROTEIRO.md` | Este roteiro |

Os arquivos auxiliares são instrumentos de pesquisa. **O produto continua sendo apenas `jms.c`.** Python e libsodium não são dependências do executável JMS. Não use `bench_driver` para proteger documentos: sua senha é pública.

## 3. Preparar o Mac

Descompacte `JMS-academico.zip`, abra o Terminal e entre na pasta extraída. Exemplo, se estiver em Downloads:

```bash
cd ~/Downloads/jms-academico
uname -m
cc --version
python3 --version
```

`uname -m` deve mostrar `arm64` para execução nativa no M1. Se mostrar `x86_64`, verifique se o Terminal/ambiente está usando Rosetta antes de executar o experimento principal.

Use Python **3.9 ou posterior**. O benchmark padrão usa somente a biblioteca padrão do Python e um compilador C. Se o compilador não estiver instalado:

```bash
xcode-select --install
```

Conclua a instalação e reabra o Terminal. Se Python não estiver disponível, instale uma versão arm64/universal2 pelo instalador oficial em https://www.python.org/downloads/macos/ ou por seu gerenciador de pacotes habitual. Não precisa de Docker para este experimento: execução nativa evita introduzir uma máquina virtual na medição.

Antes de medir:

1. Conecte o carregador e mantenha o mesmo modo de energia em todas as sessões.
2. Feche aplicações pesadas e aguarde o término de indexações e atualizações.
3. Use uma pasta local, fora de volumes de rede e de pastas sendo sincronizadas.
4. Registre se o Mac estava frio/aquecido, os aplicativos ativos e o modo de energia.
5. Reserve pelo menos 1 GiB para o ensaio padrão; para `--large`, reserve pelo menos 5 GiB livres. O script verifica uma estimativa de espaço antes de gerar os dados.

O perfil de 1 GiB escreve dezenas de GiB ao longo das repetições e verificações. É uma etapa opcional: comece com o perfil padrão, de até 100 MiB. Os arquivos grandes temporários são removidos ao término; os dados brutos do experimento permanecem.

## 4. Compilar e usar o JMS

```bash
cc -std=c99 -O2 -Wall -Wextra -Wpedantic -Werror jms.c -o jms
./jms --self-test
./jms -v
```

Resultado esperado do primeiro teste:

```text
Self-test: OK (6 known-answer checks)
```

Faça um ensaio em dados descartáveis:

```bash
printf 'Teste JMS no MacBook M1\n' > exemplo.txt
./jms -e -f exemplo.txt -o exemplo.jms
./jms -d -f exemplo.jms -o recuperado.txt
cmp exemplo.txt recuperado.txt
```

O JMS solicita a senha sem eco e pede confirmação ao cifrar. Nada aparece durante a digitação. `cmp` sem mensagem e com código de saída zero indica igualdade. Os destinos devem ser novos; o programa recusa sobrescrita, inclusive quando entrada e saída são o mesmo caminho. A senha não é aceita em argumentos, variáveis de ambiente ou entrada padrão redirecionada.

O formato novo é **JMS3**, incompatível com os arquivos da versão JMS2. Para migrar dados antigos, conserve uma cópia do executável antigo e decifre com ele antes de cifrar com esta versão. Não substitua o único meio de leitura dos seus arquivos anteriores.

## 5. Validação antes da medição

O benchmark já executa uma validação obrigatória. Para a verificação ampliada:

```bash
python3 verify.py --out verificacao-m1.json
```

Esse comando compila e verifica vetores conhecidos com `-O0`, `-O2`, `-O3` e `-O3 -flto`; executa testes de arquivos sob AddressSanitizer/UndefinedBehaviorSanitizer; e testa a interface em pseudoterminal. Ele não realiza análise estática, fuzzing, prova de tempo constante ou inspeção automática de zeroização no assembly.

Para acrescentar uma comparação independente com a biblioteca Python `cryptography`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography
python verify.py --reference --out verificacao-m1-referencia.json
python -m pip freeze > versoes-verificacao.txt
```

Essa dependência existe somente no laboratório de validação. O teste compara Poly1305 e AEAD em vários comprimentos e atualizações fragmentadas; PBKDF2 é comparado com `hashlib`. Não execute o benchmark com sanitizadores: o script compila um binário separado com `-O2`.

Se algum teste falhar, preserve o erro e não use resultados posteriores como avaliação válida. Não remova o teste para obter um relatório. Uma falha de instalação de sanitizadores exige corrigir o ambiente; não é automaticamente uma falha criptográfica.

## 6. Executar o benchmark rápido

Na pasta do projeto:

```bash
python3 benchmark.py --profile quick --out resultados-rapido
```

O nome da pasta de saída precisa ser novo. A execução:

- compila o JMS, o driver e o coletor com o mesmo compilador;
- executa vetores, testes diferenciais de PBKDF2, recuperação e rejeição de entradas;
- cria arquivos de 1 KiB e 1 MiB;
- faz um aquecimento e duas repetições por condição;
- mede cifragem, decifragem, cópia sem criptografia, PBKDF2 e AEAD em memória;
- verifica o conteúdo recuperado fora da janela medida;
- produz `relatorio.md`, `raw.csv`, `summary.csv`, `metadata.json`, `inputs.json`, `validation.json` e logs.

Abra o relatório no seu editor:

```bash
open -a TextEdit resultados-rapido/relatorio.md
```

Este é um teste do procedimento, **não o conjunto final de resultados para publicação**. O relatório identifica esse estado explicitamente.

## 7. Executar o perfil do artigo

```bash
caffeinate -i python3 benchmark.py --profile article --out resultados-m1-sessao1
```

No macOS, `caffeinate -i` evita suspensão por inatividade durante o comando. Mantenha a tampa aberta. A execução pode levar vários minutos; o script imprime a condição atual e não exige digitar senhas.

Configuração padrão:

| Dimensão | Condições |
|---|---|
| Arquivos | 1 KiB, 1 MiB, 10 MiB, 100 MiB |
| Operações de arquivo | cifrar, decifrar, copiar |
| KDF nos arquivos | PBKDF2-HMAC-SHA256, 600.000 iterações, chave de 32 bytes |
| Ensaio de latência da KDF | 100.000, 300.000, 600.000, 1.000.000 iterações |
| Microbenchmark AEAD | 64 registros de 1 MiB por amostra, AAD de 40 bytes |
| Aquecimento | 1 execução por condição, descartada |
| Amostras medidas | 7 por condição |
| Ordem | embaralhada em cada rodada, com semente registrada |
| Persistência | `fsync` do arquivo temporário de saída incluído em cifrar/decifrar/copiar |

Para acrescentar arquivos de 1 GiB:

```bash
caffeinate -i python3 benchmark.py --profile article --large --out resultados-m1-grande
```

Para ampliar a quantidade de repetições:

```bash
caffeinate -i python3 benchmark.py --profile article --repeats 15 --out resultados-m1-15
```

Faça pelo menos três sessões em condições registradas, por exemplo em momentos diferentes, conservando a mesma configuração:

```bash
caffeinate -i python3 benchmark.py --profile article --seed 20260927 --out resultados-m1-sessao2
caffeinate -i python3 benchmark.py --profile article --seed 20260928 --out resultados-m1-sessao3
```

Analise cada sessão antes de juntar os dados. O script agrega repetições dentro da sessão; **não combina sessões automaticamente**. Diferenças térmicas e de processos em segundo plano são evidências a discutir, não amostras a apagar silenciosamente.

## 8. Comparação opcional com libsodium

Para uma primeira comparação criptográfica controlada, o script suporta a variante **IETF ChaCha20-Poly1305** da libsodium em um microbenchmark. Se você já usa Homebrew:

```bash
brew install libsodium
brew --prefix libsodium
caffeinate -i python3 benchmark.py --profile article --sodium-prefix "$(brew --prefix libsodium)" --out resultados-m1-sodium
```

Sem Homebrew, forneça `--sodium-prefix /caminho/da/instalacao`, que contenha `include/sodium.h` e `lib/libsodium`. Não é necessário instalar libsodium para usar o JMS ou executar o benchmark padrão.

A comparação usa os mesmos buffers em memória, nonce por registro, AAD, tamanhos e número de operações. Os bytes cifrados e a tag são comparados entre as implementações antes da coleta. A comparação cronometrada inclui a inicialização do processo e as cópias do buffer, mas exclui PBKDF2 e arquivos. A versão da libsodium e a ligação dinâmica são registradas. O executável `jms` continua sem libsodium; apenas o driver experimental é ligado a ela.

Não escrever “JMS é mais rápido/lento que a ferramenta libsodium para arquivos”: libsodium é uma biblioteca, e o ensaio é da AEAD em registros de 1 MiB. O programa JMS cifra um arquivo como uma única mensagem AEAD. No driver opcional, ambas as condições são executadas no mesmo binário ligado à libsodium; considere isso ao discutir RSS.

**Etapa comparativa ainda em aberto:** ferramentas completas como age e GnuPG exigem protocolo próprio: mesma entrada, modalidade de senha, KDF identificada, opções de compressão, custo de derivação e formato de autenticação documentados. Não inserir linhas com números estimados. Monocypher também requer escolher e declarar construções equivalentes; não assumir que todas as APIs implementam a mesma variante IETF.

## 9. O que o relatório automático oferece

O arquivo principal é `resultados-.../relatorio.md`. Ele contém:

1. Ambiente, compilador, flags, hashes dos fontes e tamanho do executável.
2. Protocolo usado e testes concluídos.
3. Mediana, quartis, vazão em MiB/s e pico de RSS por condição.
4. Texto-base da seção experimental, preenchido com dados reais daquela execução.
5. Limitações e comparações ainda pendentes.

`raw.csv` preserva cada amostra, inclusive tempo de CPU de usuário e sistema. `summary.csv` também registra média, desvio padrão, mínimo e máximo. Para conversão ao artigo, use a tabela e adapte o texto-base ao template da revista. Os quartis descrevem dispersão; **não são intervalos de confiança**. Amostras muito curtas, especialmente cópias de 1 KiB, podem ser dominadas por lançamento do processo e resolução dos contadores.

Exemplo de estrutura de resultados, preenchida somente após rodar no Mac:

> No MacBook M1, a cifragem de arquivos de 100 MiB apresentou mediana de [s] e intervalo interquartil [Q1–Q3]. O tempo inclui derivação de chave, AEAD, I/O e sincronização do arquivo de saída. A decifragem incluiu uma cópia cifrada temporária usada para impedir mudanças entre autenticação e leitura dos dados. O pico de RSS do processo de teste foi [MiB]. As medições representam as condições de cache e energia registradas nesta sessão.

Não substituir os colchetes com resultados do Linux de desenvolvimento. O script produzirá os números do M1 quando você o executar nessa máquina.

## 10. Arquitetura e limites a descrever no artigo

- Núcleo criptográfico em C99; APIs POSIX para terminal, CSPRNG do SO e arquivos. Não é “somente biblioteca padrão C”.
- PBKDF2-HMAC-SHA256 produz 32 bytes. Padrão provisório: 600.000 iterações; política de leitura: 100.000 a 5.000.000. Limites reduzem abuso de custo no cabeçalho ainda não autenticado; não eliminam ataques de negação de serviço.
- Salt de 16 bytes e nonce de 12 bytes novos a cada cifragem, obtidos de `/dev/urandom`. Não há fallback pseudoaleatório próprio.
- ChaCha20-Poly1305 segue a construção AEAD do RFC 8439. Chave por arquivo derivada do salt; nonce não é reutilizado intencionalmente.
- Cabeçalho serializado de 56 bytes. Bytes 0–39 são AAD; tag de 16 bytes em 40–55; ciphertext começa em 56. Campos são serializados explicitamente, sem gravar `struct`.
- Limite de plaintext: 274.877.906.880 bytes, ou 256 GiB menos 64 bytes, por mensagem AEAD. O código recusa ultrapassá-lo, inclusive durante a leitura.
- Autenticação precede a criação de texto claro. A decifragem usa um snapshot cifrado temporário e privado; não relê o arquivo mutável do usuário depois da autenticação.
- Memória de processamento limitada por buffers, mas uso temporário de disco cresce com o tamanho do arquivo. Snapshot e saída podem coexistir.
- Saída temporária tem permissão 0600 e é publicada por `link`, sem sobrescrita, no mesmo sistema de arquivos. Requer diretório de saída confiável e suporte a hard links: use o volume local do macOS, evitando FAT/exFAT para este procedimento.
- `fsync` não é uma garantia completa de persistência física no macOS. Não se usa `F_FULLFSYNC` nem sincronização de diretório.
- Limpeza explícita de buffers e contextos sensíveis reduz a permanência dessas cópias. Não apaga garantidamente registradores, cópias do compilador, swap, dumps ou conteúdo do SSD.
- Interrupções durante a digitação restauram o eco nos sinais tratados (INT, TERM, HUP, QUIT, TSTP). SIGKILL e perda de energia não são tratáveis. Interrupção abrupta durante o processamento pode deixar um arquivo `.tmp.*` privado, inclusive com plaintext já autenticado; isso não equivale a apagamento seguro.
- Arquivos fonte não são apagados. O programa não é destinado a adversários que controlam o processo, o SO ou o diretório de saída. Senhas fracas continuam sujeitas a ataque offline; PBKDF2 não tem a resistência baseada em memória de Argon2.

## 11. Questões de pesquisa e tarefas restantes

**RQ1 — Corretude e robustez:** relatar os vetores e testes realmente executados, os compiladores e plataformas verificados. Testes não provam ausência de vulnerabilidades. Acrescentar análise estática, fuzzing e revisão independente antes de reivindicar robustez ampla.

**RQ2 — Minimalismo e recursos:** apresentar arquivo-fonte único, linhas físicas, bytes do executável, dependências dinâmicas e RSS. Esses são indicadores distintos; não converter tamanho em “segurança” ou “auditabilidade comprovada”. Para medir auditabilidade, definir um protocolo próprio de revisão.

**RQ3 — Desempenho:** preencher com os resultados do M1, mantendo separados custo de KDF, microbenchmark AEAD e operações completas de arquivo. Acrescentar as comparações pertinentes sem misturar configurações de segurança diferentes.

Para inspecionar zeroização no compilador do Mac:

```bash
cc -std=c99 -O2 -S jms.c -o jms-O2.s
cc -std=c99 -O3 -S jms.c -o jms-O3.s
cc -std=c99 -O3 -flto jms.c -o jms-lto
otool -tvV jms-lto > jms-lto-disassembly.txt
```

A presença de um símbolo não basta: `secure_memzero` pode ser inline. Revise os stores nas rotinas que manipulam senha, chaves e contextos. Registre o método e as limitações; não conclua “zeroização comprovada” apenas porque o programa passou nos testes funcionais.

## 12. Referências e disponibilização

- PBKDF2: RFC 8018, https://www.rfc-editor.org/rfc/rfc8018
- ChaCha20-Poly1305 e vetores: RFC 8439, https://www.rfc-editor.org/rfc/rfc8439
- HMAC-SHA256, vetores: RFC 4231, https://www.rfc-editor.org/rfc/rfc4231
- Variante IETF na libsodium: https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction

Preserve os fontes exatos, os hashes, os logs de validação, os relatórios e os CSVs junto da versão submetida do artigo. Ao publicar o repositório, escolha explicitamente a licença do seu código; este pacote não atribui uma licença em seu nome. Cite as especificações e declare a origem do código inicial e o uso de assistência de IA conforme a política editorial adotada.
