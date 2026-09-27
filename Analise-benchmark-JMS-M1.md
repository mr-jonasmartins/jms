# JMS 3.0 — análise consolidada de três sessões no Apple M1

Este relatório consolida as três sessões do perfil `article`, com comparação AEAD com libsodium, realizadas em 26 de setembro de 2026. A análise foi feita sobre os registros dos arquivos `resultados-m1-sodium.zip` e `Arquivo.zip`; os binários desses arquivos não foram executados durante a conferência. Foram verificados registros, estatísticas, tamanhos e hashes.

No repositório, os registros são organizados em `resultados/`, preservando os nomes das três pastas de sessão. Consulte o [README](README.md) para uso e reprodução e o [roteiro](ROTEIRO.md) para o procedimento detalhado.

## 1. Verificação de consistência

As três sessões são internamente consistentes e mantêm a mesma configuração de software e hardware registrada. Foram analisadas **378 amostras medidas: 18 condições × 7 repetições × 3 sessões**. As 54 execuções de aquecimento declaradas pelo protocolo foram descartadas e não estão incluídas nessa contagem.

Foram recalculadas medianas, quartis, médias, desvios padrão, mínimos, máximos, vazões e medianas de pico RSS de cada condição a partir dos dados brutos. Todos os valores correspondem aos respectivos arquivos `summary.csv`. Cada condição contém exatamente as repetições 1 a 7, e cada rodada contém as posições de execução 0 a 17, sem duplicação ou lacunas.

Os quatro hashes dos fontes, os parâmetros de compilação, a versão da libsodium, o ambiente e as configurações de repetição coincidem. O tamanho e o hash do executável JMS de cada ZIP correspondem aos metadados; o hash desse binário também é idêntico entre as sessões. Os registros de validação são iguais e a última medição de cada sessão corresponde à última linha do CSV. Essas verificações sustentam a consistência dos registros; não equivalem a uma reprodução independente dos tempos ou a uma certificação da origem dos dados.

As operações criptográficas apresentaram pequena variação das medianas entre as sessões avaliadas. A cópia sem criptografia apresentou maior variação, especialmente nos arquivos pequenos. A libsodium manteve maior vazão no microbenchmark de AEAD em todas as sessões.

## 2. Ambiente e organização das sessões

| Item | Configuração comum |
|---|---|
| CPU e arquitetura | Apple M1, arm64 |
| RAM física | 8.589.934.592 bytes = 8 GiB |
| Sistema registrado | macOS 27.0 |
| Compilador | Apple clang 21.0.0 |
| Flags | `-std=c99 -O2 -Wall -Wextra -Wpedantic -Werror` |
| Python | 3.9.6 |
| libsodium | 1.0.22, conforme cabeçalho e caminhos registrados |
| KDF nas operações de arquivo | PBKDF2-HMAC-SHA256, 600.000 iterações |
| Repetições por condição/sessão | 7 medidas, precedidas de 1 aquecimento descartado |
| Fonte JMS | 29.367 bytes; 786 linhas físicas |
| Executável JMS | 52.304 bytes = 51,08 KiB |
| Dependência dinâmica de produção | `libSystem.B.dylib` |
| Dependências do driver comparativo | `libSystem.B.dylib` e libsodium |

| Sessão | Diretório | Início em 26/09/2026, America/Bahia | Semente |
|---|---|---|---:|
| 1 | `resultados-m1-sodium` | 18:38:46 | 20260926 |
| 2 | `resultados-m1-sodium-sessao2` | 19:19:52 | 20260927 |
| 3 | `resultados-m1-sodium-sessao3` | 19:22:55 | 20260928 |

São três execuções no mesmo equipamento e no mesmo dia, cujos inícios abrangem aproximadamente 44 minutos. Não há evidência de reinicializações, controle térmico, isolamento de processos ou independência estatística entre sessões. Os resultados caracterizam repetibilidade de curto prazo nesse ambiente.

**Detalhe metodológico:** no script utilizado, a semente controla tanto a geração dos arquivos sintéticos quanto o embaralhamento da ordem dos testes. Os hashes dos arquivos de entrada diferem entre as sessões, conforme `inputs.json`. Permanecem iguais os tamanhos e o procedimento de geração: blocos pseudoaleatórios determinísticos de 1 MiB, repetidos nos arquivos maiores. Logo, as mudanças entre sessões não se restringiram à ordem de execução e as entradas não foram byte a byte idênticas. O microbenchmark AEAD utiliza os mesmos buffers zerados em todas as sessões.

## 3. Critério de consolidação

Primeiro foi calculada a mediana das sete medições de cada condição em cada sessão. O valor consolidado é a **mediana dessas três medianas**, dando o mesmo peso às sessões. A vazão consolidada é o tamanho processado em MiB dividido por esse tempo consolidado.

A amplitude relativa entre sessões foi calculada por:

$$
A_{rel}=100\,\frac{\max(m_1,m_2,m_3)-\min(m_1,m_2,m_3)}{\operatorname{mediana}(m_1,m_2,m_3)}.
$$

Ela descreve a dispersão das três medianas, não a dispersão de todas as amostras, um coeficiente de variação ou um intervalo de confiança. Há 21 observações por condição, agrupadas em três sessões; elas não foram tratadas como 21 sessões independentes. Nenhuma medição lenta foi excluída. Os quartis e demais estatísticas de cada sessão permanecem nos CSVs originais.

## 4. Resultados consolidados

### 4.1. Cifragem de arquivos

| Condição | Sessão 1 (s) | Sessão 2 (s) | Sessão 3 (s) | Mediana das medianas (s) | Amplitude relativa | Vazão consolidada (MiB/s) |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB | 0,612413 | 0,613130 | 0,613303 | 0,613130 | 0,15% | 0,001593 |
| 1 MiB | 0,618430 | 0,617221 | 0,617262 | 0,617262 | 0,20% | 1,62 |
| 10 MiB | 0,664090 | 0,669720 | 0,668142 | 0,668142 | 0,84% | 14,97 |
| 100 MiB | 1,142934 | 1,151983 | 1,148387 | 1,148387 | 0,79% | 87,08 |

### 4.2. Decifragem de arquivos

| Condição | Sessão 1 (s) | Sessão 2 (s) | Sessão 3 (s) | Mediana das medianas (s) | Amplitude relativa | Vazão consolidada (MiB/s) |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB | 0,612613 | 0,612515 | 0,611226 | 0,612515 | 0,23% | 0,001594 |
| 1 MiB | 0,620170 | 0,624435 | 0,620220 | 0,620220 | 0,69% | 1,61 |
| 10 MiB | 0,668874 | 0,674288 | 0,672924 | 0,672924 | 0,80% | 14,86 |
| 100 MiB | 1,167195 | 1,185946 | 1,173694 | 1,173694 | 1,60% | 85,20 |

A cifragem de 100 MiB teve valor consolidado de **1,148387 s (87,08 MiB/s)**, com amplitude relativa das medianas de 0,79%. A decifragem apresentou **1,173694 s (85,20 MiB/s)**, com amplitude relativa de 1,60%. Nas oito condições de arquivo, essa amplitude permaneceu abaixo de 1,60%, considerando os valores não arredondados.

Esses tempos incluem criação do processo, KDF, AEAD, I/O e `fsync` do arquivo temporário de saída. A digitação da senha está excluída: o driver chama a mesma função do CLI com uma senha pública de teste. A decifragem inclui a criação e a releitura de uma cópia cifrada temporária autenticada. Não foi realizada uma ablação com e sem essa cópia, de modo que a diferença entre cifrar e decifrar não isola o custo dessa proteção.

### 4.3. Derivação de chave

| Condição | Sessão 1 (s) | Sessão 2 (s) | Sessão 3 (s) | Mediana das medianas (s) | Amplitude relativa |
|---|---:|---:|---:|---:|---:|
| 100.000 iterações | 0,104172 | 0,107034 | 0,106149 | 0,106149 | 2,70% |
| 300.000 iterações | 0,305487 | 0,308500 | 0,308542 | 0,308500 | 0,99% |
| 600.000 iterações | 0,608185 | 0,609674 | 0,609529 | 0,609529 | 0,24% |
| 1.000.000 de iterações | 1,011513 | 1,012081 | 1,011197 | 1,011513 | 0,09% |

O valor consolidado de PBKDF2 com 600.000 iterações foi **0,609529 s**, próximo ao tempo consolidado para cifrar 1 KiB, de 0,613130 s. A observação é compatível com a predominância do custo fixo da KDF em arquivos pequenos. Não se deve subtrair essas medianas, obtidas em experimentos distintos, para declarar um tempo instrumentado exclusivo da cifra ou uma fração exata de tempo de cada componente.

A latência cresceu aproximadamente em proporção ao número de iterações. O ensaio mede esse custo no equipamento, sem determinar por si um parâmetro ótimo de resistência a ataques de senha.

### 4.4. AEAD em memória: JMS e libsodium

Cada amostra processou 64 registros independentes de 1 MiB, totalizando 64 MiB, com AAD de 40 bytes por registro. Trata-se de cifragem AEAD em memória; não inclui KDF, arquivos ou comparação de desempenho da decifragem AEAD. O tempo inclui os custos auxiliares do processo e do driver, como alocação, inicialização, cópia de buffers e limpeza prevista no código.

| Condição | Sessão 1 (s) | Sessão 2 (s) | Sessão 3 (s) | Mediana das medianas (s) | Amplitude relativa | Vazão consolidada (MiB/s) |
|---|---:|---:|---:|---:|---:|---:|
| AEAD JMS | 0,300610 | 0,305084 | 0,303068 | 0,303068 | 1,48% | 211,17 |
| libsodium | 0,169247 | 0,169851 | 0,170216 | 0,169851 | 0,57% | 376,80 |

| Sessão | Vazão JMS (MiB/s) | Vazão libsodium (MiB/s) | Razão libsodium/JMS |
|---|---:|---:|---:|
| 1 | 212,90 | 378,15 | 1,776 |
| 2 | 209,78 | 376,80 | 1,796 |
| 3 | 211,17 | 375,99 | 1,780 |

A libsodium apresentou entre **1,776 e 1,796 vez a vazão do JMS**, conforme a sessão. A mediana dessas três razões foi **1,780**, equivalente a aproximadamente 78,0% mais vazão. A razão calculada diretamente a partir das duas vazões consolidadas é 1,784; são formas distintas de agregação e não devem ser confundidas.

Todas as amostras da libsodium foram mais rápidas que todas as amostras do JMS nesse microbenchmark, considerando as três sessões. O maior tempo da libsodium foi 0,190529 s, e o menor do JMS foi 0,300278 s. A separação observada é descritiva; não foi aplicado teste de significância nem estimado intervalo de confiança.

A diferença não pode ser atribuída exclusivamente ao minimalismo, à vetorização, à linguagem ou a uma técnica específica, pois esses fatores não foram isolados. Também não é uma comparação entre ferramentas completas de proteção de arquivos.

### 4.5. Cópia sem criptografia: referência de I/O

| Condição | Sessão 1 (s) | Sessão 2 (s) | Sessão 3 (s) | Mediana das medianas (s) | Amplitude relativa | Vazão consolidada (MiB/s) |
|---|---:|---:|---:|---:|---:|---:|
| 1 KiB | 0,003474 | 0,006854 | 0,006363 | 0,006363 | 53,12% | 0,153475 |
| 1 MiB | 0,004051 | 0,007822 | 0,007786 | 0,007786 | 48,43% | 128,44 |
| 10 MiB | 0,009781 | 0,013210 | 0,012695 | 0,012695 | 27,01% | 787,71 |
| 100 MiB | 0,045302 | 0,041050 | 0,039846 | 0,041050 | 13,29% | 2436,05 |

A amplitude relativa das medianas foi de 53,12% para 1 KiB, 48,43% para 1 MiB, 27,01% para 10 MiB e 13,29% para 100 MiB. Essas operações curtas são mais sensíveis, em termos relativos, a custos de lançamento do processo, I/O e atividade do ambiente. Os registros disponíveis não isolam a causa da variação.

Essa referência deve permanecer no relatório, acompanhada de sua dispersão. Não é adequado afirmar estabilidade uniforme de todos os testes, usar a vazão de cópia como velocidade física do SSD ou subtrair o tempo de cópia do tempo de cifragem para estimar desempenho puro da AEAD.

### 4.6. Memória e tamanho

A mediana do pico de RSS do driver nas condições de cifragem e decifragem de arquivos foi **1,625 MiB nas três sessões**, para os tamanhos de 1 KiB a 100 MiB. Isso é compatível com o uso de buffers de tamanho limitado. Não prova consumo constante para qualquer tamanho de entrada e não inclui o consumo temporário de disco nem todo o cache do SO.

No microbenchmark, as medianas de pico de RSS foram 3,671875 MiB para JMS e 3,718750 MiB para libsodium em todas as sessões. Trata-se do processo do driver, que está ligado à libsodium nas duas condições desta execução comparativa. A diferença pequena não fundamenta uma vantagem geral de memória do JMS.

O executável de produção permaneceu em 52.304 bytes, cerca de 51,08 KiB, com ligação apenas à biblioteca do sistema. O fonte contém 786 linhas físicas. Não foi medido um executável alternativo de arquivo completo com funcionalidades equivalentes; esses números caracterizam o artefato, sem demonstrar vantagem comparativa de tamanho, auditabilidade ou segurança.

## 5. Corretude registrada e limites da evidência

As três sessões registram a conclusão dos mesmos testes: seis verificações internas de resposta conhecida, PBKDF2 contra `hashlib`, 13 recuperações de arquivos, senha incorreta, 23 entradas adulteradas ou inválidas, preservação de destino existente/link simbólico, rejeição de entrada igual à saída e geração de salt/nonce diferentes em duas cifragens. A comparação com libsodium confirmou a igualdade de ciphertext e tag para uma mensagem de 1 MiB antes da coleta.

Os arquivos analisados não contêm o relatório de `verify.py --reference`; portanto, os testes ampliados com Python `cryptography`, sanitizadores ou terminal no M1 não são contabilizados como evidência desta análise. Relatórios adicionais, se disponíveis, devem identificar sua execução e a versão dos fontes, sem serem confundidos com os registros destas três sessões.

Os ensaios funcionais não constituem auditoria independente, prova de tempo constante, avaliação abrangente de falhas de I/O ou prova de zeroização sob otimização.

## 6. Limitações experimentais

A avaliação ocorreu em um único equipamento, com três sessões no mesmo dia. Não foram controlados afinidade de núcleos, frequência, temperatura ou processos em segundo plano. As sessões não representam amostras independentes de equipamentos ou ambientes distintos.

O cache do sistema não foi esvaziado. A preparação, o aquecimento e as verificações fora da janela cronometrada podem influenciar o estado do cache entre amostras. O uso de `fsync` não foi complementado por `F_FULLFSYNC` ou sincronização do diretório. A referência de cópia não mede isoladamente o desempenho físico do armazenamento.

As medições de RSS abrangem o driver e suas bibliotecas. A comparação externa se restringe à cifragem AEAD em memória; não foram medidas ferramentas completas sob configurações equivalentes. A alteração das sementes também mudou as entradas sintéticas, mantendo seus tamanhos e método de geração.

Não foram estimados intervalos de confiança nem realizados testes de significância. A síntese descreve as medições observadas. Os testes funcionais não substituem auditoria independente, análise de canais laterais ou inspeção da limpeza de memória no binário.

## 7. Conclusão experimental

As três sessões forneceram evidência de repetibilidade de curto prazo para o processamento criptográfico do JMS no ambiente avaliado. O artefato manteve um executável de aproximadamente 51 KiB e apresentou vazão consolidada de 87,08 MiB/s na cifragem de arquivos de 100 MiB, incluindo a derivação de chave. No ensaio AEAD em memória, a libsodium manteve maior vazão nas três sessões. Os resultados permitem descrever o custo computacional da implementação experimental e sua diferença frente à referência utilizada, preservando o minimalismo como uma característica de projeto, sem atribuir a ele superioridade de desempenho, segurança ou auditabilidade.


## 8. Fontes e rastreabilidade

- Sessão 1: `resultados-m1-sodium.zip` → `resultados/resultados-m1-sodium/`.
- Sessões 2 e 3: `Arquivo.zip` → `resultados/resultados-m1-sodium-sessao2/` e `resultados/resultados-m1-sodium-sessao3/`.
- Em cada pasta: `raw.csv`, `summary.csv`, `metadata.json`, `validation.json`, `inputs.json` e `measurement.json`.
- Executável `jms`: conferência de tamanho e hash, sem execução local.
- Fonte JMS comum: SHA-256 `22c73a2dc15f39239d455c08401e2481dc82fe3d29a3028d7847a1d13fe39c0f`.
- Executável JMS comum: SHA-256 `72d69afd1f64af95aa4244dd3e20ab3e0a28d84090a2ceb416867c122a2264eb`.

MiB/s usa 1 MiB = 1.048.576 bytes; KiB usa 1 KiB = 1.024 bytes. Os cálculos utilizam os valores originais não arredondados. Os tempos mostrados nas tabelas são medianas de sessão, e não medições individuais. As amplitudes são calculadas sobre as três medianas.

Os metadados originais registram os hashes dos fontes e as versões do ambiente. Caminhos absolutos neles contidos descrevem a máquina da coleta; não são requisitos para repetir os ensaios em outro diretório. Os ZIPs podem ser mantidos como arquivo histórico, enquanto os registros textuais são publicados nas pastas acima.

O commit ou tag da publicação deve ser associado ao artigo quando estiver disponível. Alterações posteriores no código exigem nova identificação de versão; seus resultados não devem ser misturados silenciosamente com esta coleta.
