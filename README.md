# JMS (Just Message Security) v2.0

O **JMS** é um utilitário de criptografia de arquivos de linha de comando (*CLI*), leve e autossuficiente, desenvolvido em linguagem C. O projeto foi desenhado com foco em portabilidade, transparência e segurança de memória, sem depender de bibliotecas externas complexas como OpenSSL ou libsodium.

## Estratégia Criptográfica

O JMS utiliza algoritmos modernos e robustos:

* **Cifra:** ChaCha20 (cifra de fluxo de alto desempenho).
* **Autenticação:** HMAC-SHA256 (paradigma *Encrypt-then-MAC*).
* **Derivação de Chave:** KDF iterativo (200.000 iterações) com *salt* dinâmico.
* **Segurança de Memória:** Implementação de limpeza segura de *buffers* (*zero-fill*) para mitigar vazamentos de dados na RAM.

## Como usar

### Pré-requisitos

* Um compilador C (GCC ou Clang).
* Ambiente UNIX (macOS/Linux) ou Windows (com suporte a Win32 API).

### Compilação

```bash
gcc jms.c -o jms

```

### Comandos

O JMS possui uma interface simples e intuitiva:

**Para criptografar um arquivo:**

```bash
./jms -f arquivo.pdf -c "sua-senha-segura" -o arquivo.jms

```

**Para descriptografar um arquivo:**

```bash
./jms -f arquivo.jms -d "sua-senha-segura" -o arquivo_original.pdf

```

## Diferenciais Técnicos

* **Zero Dependências:** Código compacto, fácil de auditar e compilar em qualquer lugar.
* **Resiliência:** O sistema utiliza comparação de assinatura (*MAC*) em tempo constante, prevenindo ataques de temporização (*timing attacks*).
* **Gestão de Memória:** Diferente de muitas ferramentas que confiam na abstração do compilador, o JMS força a sobrescrita de chaves na memória RAM após o uso, protegendo contra *dead store elimination*.

## Contribuição

Este projeto é de código aberto. Se deseja reportar *bugs*, sugerir melhorias ou realizar auditorias de segurança, sinta-se à vontade para abrir uma *Issue* ou enviar um *Pull Request*.

## Licença

Este projeto é distribuído sob os termos da licença [Inserir tipo de licença, ex: MIT].

---

### Dicas adicionais para o seu GitHub:

1. **Licença:** Não esqueça de adicionar um arquivo `LICENSE` no seu repositório (ex: MIT ou GPLv3).
2. **Imagens:** Se o seu artigo científico incluir aquele diagrama de funcionamento do cabeçalho ou das funções booleanas (que comentamos antes), adicione uma pasta `/docs` no GitHub e coloque a imagem lá, referenciando no README assim: `![Funcionamento do Cabeçalho](docs/header_layout.png)`.
3. **Tags:** No lado direito do repositório, não esqueça de marcar os *Topics* como `c`, `cryptography`, `security` e `cha-cha-20`.
