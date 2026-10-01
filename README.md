# Vault — Manual de Arquitetura, Segurança e Operação Técnica

Cofre corporativo de segredos (*Secrets Manager appliance*) com criptografia de envelope (Envelope Encryption), banco de dados transacional embutido com suporte a replicação síncrona/assíncrona, motor de PKI interna (X.509 / mTLS mútuo), controle de acesso granular baseado em papéis (RBAC/ACL) e trilha de auditoria imutável.

---

## Sumário

1. [Visão Geral e Arquitetura do Sistema](#1-visão-geral-e-arquitetura-do-sistema)
   - [Envelope Encryption (KEK e DEK)](#envelope-encryption-kek-e-dek)
   - [Identidades de Serviço (App IDs) e Sessões JWT](#identidades-de-serviço-app-ids-e-sessões-jwt)
   - [Modelo de Cofres lógicos e RBAC](#modelo-de-cofres-lógicos-e-rbac)
2. [Topologia de Rede e Segurança Zero-Trust](#2-topologia-de-rede-e-segurança-zero-trust)
   - [Isolamento de Infraestrutura](#isolamento-de-infraestrutura)
   - [Proteção Ativa de Documentação (/docs, /openapi.json)](#proteção-ativa-de-documentação-docs-openapijson)
   - [Princípio do Menor Privilégio no PostgreSQL](#princípio-do-menor-privilégio-no-postgresql)
3. [Versionamento Granular de Segredos](#3-versionamento-granular-de-segredos)
   - [Estrutura do Histórico Imutável](#estrutura-do-histórico-imutável)
   - [Consulta de Versões Específicas (?version=X)](#consulta-de-versões-específicas-versionx)
   - [Controles de Segurança do Parâmetro](#controles-de-segurança-do-parâmetro)
4. [Alta Disponibilidade, DR e Replicação WAL](#4-alta-disponibilidade-dr-e-replicação-wal)
   - [Papéis dos Nós (Primary vs Standby)](#papéis-dos-nós-primary-vs-standby)
   - [Comportamento Read-Only e Código HTTP 421](#comportamento-read-only-e-código-http-421)
   - [Escalabilidade Horizontal (N Standbys / Followers)](#escalabilidade-horizontal-n-standbys--followers)
5. [Motor PKI Interno e mTLS Obrigatório](#5-motor-pki-interno-e-mtls-obrigatório)
   - [Autoridade Certificadora Raiz (Root CA)](#autoridade-certificadora-raiz-root-ca)
   - [Emissão de Certificados com SANs (IPs e DNS)](#emissão-de-certificados-com-sans-ips-e-dns)
   - [mTLS Estrito no PostgreSQL (clientcert=verify-full)](#mtls-estrito-no-postgresql-clientcertverify-full)
   - [Suporte a BYO-Cert (PKI Corporativa)](#suporte-a-byo-cert-pki-corporativa)
6. [CLI Unificada (vaultctl)](#6-cli-unificada-vaultctl)
   - [vaultctl init](#vaultctl-init)
   - [vaultctl seed standby](#vaultctl-seed-standby)
   - [vaultctl join](#vaultctl-join)
   - [vaultctl promote](#vaultctl-promote)
   - [vaultctl rescue](#vaultctl-rescue)
   - [vaultctl certs inspect](#vaultctl-certs-inspect)
7. [Guia de Deploy Passo a Passo](#7-guia-de-deploy-passo-a-passo)
   - [Deploy Rápido em Host Único (deploy.py)](#cenário-a-deploy-rápido-em-host-único-deploypy)
   - [Deploy Multi-VPS com Seeds (Estilo Conjur)](#cenário-b-deploy-multi-vps-com-seeds-estilo-conjur)
   - [Distribuição Offline (Air-Gapped)](#distribuição-offline-air-gapped)
8. [Failover Manual e Proteção Anti-Split-Brain](#8-failover-manual-e-proteção-anti-split-brain)
9. [Resgate de Emergência Offline (Break-Glass)](#9-resgate-de-emergência-offline-break-glass)
10. [Referência Completa da API REST](#10-referência-completa-da-api-rest)
11. [Dicionário de Códigos de Erro da Plataforma](#11-dicionário-de-códigos-de-erro-da-plataforma)

---

## 1. Visão Geral e Arquitetura do Sistema

O Vault é um appliance autônomo projetado para proteger segredos de aplicações, senhas de banco de dados, chaves de API e certificados com segurança de nível bancário.

```text
 ┌──────────────────────────────────────────────────────────────┐
 │                      VAULT CONTAINER                         │
 │                                                              │
 │   ┌────────────────────────┐    ┌────────────────────────┐   │
 │   │    FastAPI (Uvicorn)   │    │  PostgreSQL 17 interno │   │
 │   │    - HTTPS / Bearer    │    │  - NOSUPERUSER         │   │
 │   │    - RBAC & Validação  │    │  - mTLS verify-full    │   │
 │   │    - AES-256-GCM       │    │  - WAL Streaming       │   │
 │   └───────────┬────────────┘    └───────────▲────────────┘   │
 │               │ Loopback (Unix / 127.0.0.1) │                │
 │               └─────────────────────────────┘                │
 └──────────────────────────────┬───────────────────────────────┘
                                │
                 /run/secrets/master.key (:ro)
```

### Envelope Encryption (KEK e DEK)
Para garantir que a chave mestra nunca precise ser exposta e que segredos individuais possam ser rotacionados independentemente:
1. **Master Key (KEK — Key Encryption Key):**
   - Chave simétrica de 256 bits gerada aleatoriamente no bootstrapping (`vaultctl init`).
   - Carregada **exclusivamente na memória volátil** do processo (`MasterKeyHolder`).
   - **Nunca** é gravada no banco de dados, **nunca** trafega pela API e **nunca** é impressa em logs.
2. **DEK por Secret (Data Encryption Key):**
   - Cada segredo e cada versão possuem uma DEK individual gerada aleatoriamente.
   - O payload do segredo é cifrado com a DEK via **AES-256-GCM** (criptografia autenticada).
   - A DEK é cifrada com a Master Key e persistida na coluna `encrypted_dek`.
   - Atualizações (`PUT /secrets/{name}`) geram uma **nova DEK**, rotacionando a chave do segredo sem reescrever o restante do cofre.

### Identidades de Serviço (App IDs) e Sessões JWT
O cofre não autentica usuários humanos diretamente na API principal; autentica **identidades de serviço (App IDs)**:
* **Credencial:** Identificador único (`app_name`) + segredo em alta entropia (`app_secret`), protegido por hash **bcrypt**.
* **Origem Estrita:** Cada App ID é obrigatoriamente associado a um IP ou bloco CIDR permitido (`allowed_ip`).
* **Sessão Efêmera:** A troca de credenciais em `POST /auth/token` emite um JWT assinado com chave interna de 256 bits, com TTL configurável (padrão: 15 minutos).
* **Validação Contínua:** O IP de origem do cliente é verificado em **todas** as requisições subsequentes ao validar o token Bearer.

### Modelo de Cofres lógicos e RBAC
Os recursos são organizados hierarquicamente:
* **Vaults (Cofres):** Contêineres lógicos (ex.: `financeiro`, `infraestrutura`, `pagamentos`).
* **Secrets (Segredos):** Registros identificados pelo caminho do cofre (ex.: `financeiro/db-password`).
* **Permissões Granulares:**
  - `create`: Permissão de provisionamento (global ou por cofre).
  - `read`: Permissão de descriptografia e leitura do valor.
  - `update`: Permissão de rotação de valor e DEK.
  - `delete`: Permissão de expurgo do segredo e histórico.

---

## 2. Topologia de Rede e Segurança Zero-Trust

```text
[ Aplicações Clientes ]                 [ Administrador ]
       │                                        │
       │ IP Autorizado + Bearer JWT             │ IP Autorizado do Admin
       ▼                                        ▼
┌──────────────────────────────────────────────────────────────┐
│                       VAULT ENGINE                           │
│                                                              │
│  • Bloqueio de IP fora da whitelist (403 Forbidden)         │
│  • Swagger (/docs, /openapi.json) exclusivo do admin (404)   │
│  • Prevenção contra spoofing de cabeçalhos proxy             │
│  • PostgreSQL restrito a localhost + mTLS com certificados   │
└──────────────────────────────────────────────────────────────┘
```

### Isolamento de Infraestrutura
* Por padrão, a porta de banco de dados (`5432`) não escuta em interfaces públicas (`listen_addresses='localhost'`). A comunicação API ↔ Banco é estritamente via loopback interna do container.
* Em topologias distribuídas (múltiplas VPSs), a porta do banco opera com **mTLS mandatório** e deve ser protegida por firewall/Security Group liberando tráfego exclusivamente para os IPs dos nós pares.

### Proteção Ativa de Documentação (/docs, /openapi.json)
Para eliminar a superfície de ataque e evitar enumeração de rotas por agentes maliciosos:
* As rotas `/docs`, `/redoc` e `/openapi.json` são interceptadas via middleware antes de qualquer processamento.
* Apenas conexões com origem no IP ou CIDR autorizado para identidades administrativas ativas (`is_admin=True, active=True`) conseguem visualizar a documentação.
* **Comportamento para IPs não autorizados:** A API responde com **`HTTP 404 Not Found`** (e não 403), mascarando completamente a existência dos endpoints Swagger/OpenAPI.
* Pode ser fixado estaticamente via variável de ambiente: `DOCS_ALLOWED_IP=10.10.20.37/32`.

### Princípio do Menor Privilégio no PostgreSQL
* O usuário da aplicação (`vault`) opera como `NOSUPERUSER NOCREATEDB NOCREATEROLE`.
* A cada inicialização, o container revoga permissões de superusuário caso existam.
* A senha do banco é gerada aleatoriamente com 32 bytes de alta entropia (`secrets.token_urlsafe(32)`) armazenada em arquivo de permissão restrita `0600`.

---

## 3. Versionamento Granular de Segredos

O Vault implementa versionamento imutável de segredos, preservando o histórico de alterações para auditoria, rastreabilidade e rollback.

```text
Tabela secrets (Último estado)
└── id, name, vault_id, version=3, encrypted_dek, ciphertext

Tabela secret_versions (Histórico completo)
├── version=1 | dek_v1 | ciphertext_v1 | created_by | timestamp
├── version=2 | dek_v2 | ciphertext_v2 | created_by | timestamp
└── version=3 | dek_v3 | ciphertext_v3 | created_by | timestamp
```

### Estrutura do Histórico Imutável
* Ao criar um segredo (`POST /secrets`), a versão `1` é registrada.
* Ao atualizar um segredo (`PUT /secrets/{name}`):
  1. Uma nova chave de dados (DEK) é gerada.
  2. O novo valor é cifrado e a DEK é selada com a Master Key.
  3. O contador `version` é incrementado (`1 → 2 → 3`).
  4. Um registro imutável é inserido na tabela `secret_versions`.
* Ao excluir o segredo (`DELETE /secrets/{name}`), todas as versões históricas são expurgadas em cascata (`CASCADE`).

### Consulta de Versões Específicas (?version=X)
* **Sem parâmetro (padrão):** Retorna imediatamente a última versão ativa:
  ```http
  GET /secrets/financeiro/db-password
  ```
* **Com parâmetro de versão:** Recupera uma versão histórica específica:
  ```http
  GET /secrets/financeiro/db-password?version=2
  ```

### Controles de Segurança do Parâmetro
1. **Validação de Limites Rígidos:** O parâmetro é validado na camada HTTP com `ge=1` e `le=2147483647` (máximo suportado por inteiros de 32 bits no PostgreSQL), prevenindo erros de estouro de memória ou injeções.
2. **Fail-Closed RBAC:** A verificação de permissão de leitura ocorre **antes** de checar a existência da versão. Um App ID não autorizado recebe `403` sem conseguir discernir quais versões existem.
3. **Isolamento Anti-IDOR:** A consulta histórica amarra obrigatoriamente o UUID do secret:
   ```python
   filter(SecretVersion.secret_id == secret.id, SecretVersion.version == version)
   ```
4. **Auditoria por Versão:** A trilha de auditoria registra explicitamente a versão recuperada no campo de detalhe (`detail="version=2"`).

---

## 4. Alta Disponibilidade, DR e Replicação WAL

O Vault suporta arquiteturas com Disaster Recovery (DR) ativo e escalabilidade de leitura com N réplicas Standby conectadas a um nó Líder (Primário).

```text
                           [ Nó Primário (Líder) ]
                         (Escrita & Leitura - :8000)
                                      │
            ┌─────────────────────────┴─────────────────────────┐
    Streaming WAL (mTLS)                        Streaming WAL (mTLS)
            ▼                                           ▼
  [ Standby 1 (DR Local) ]                    [ Standby 2 (Cloud / Edge) ]
(Somente Leitura - HTTP 421)                 (Somente Leitura - HTTP 421)
```

### Papéis dos Nós (Primary vs Standby)
A rota pública `GET /health` identifica dinamicamente o papel operacional do nó:
* **Nó Primário:**
  ```json
  {"status": "ok", "role": "primary", "read_only": false}
  ```
* **Nó Standby (DR):**
  ```json
  {"status": "ok", "role": "standby", "read_only": true}
  ```

### Comportamento Read-Only e Código HTTP 421
* **Leituras Permitidas:** Aplicações podem emitir tokens (`POST /auth/token`) e consultar segredos (`GET /secrets/{name}`) diretamente em qualquer nó Standby, permitindo distribuir a carga de leitura geograficamente.
* **Escritas Rejeitadas:** Tentativas de escrita (`POST /secrets`, `PUT`, `DELETE`, `/vaults`, `/admin`) em nós Standby são interceptadas no middleware e rejeitadas com **`HTTP 421 Misdirected Request`** (`VLT-5001`), orientando o cliente ou Load Balancer a direcionar a requisição ao Primário.

### Escalabilidade Horizontal (N Standbys / Followers)
O motor PostgreSQL suporta múltiplos receptores de WAL concorrentes (`max_wal_senders`). Cada nó Standby replica de forma autônoma sem interferir nos demais.

---

## 5. Motor PKI Interno e mTLS Obrigatório

Para comunicação segura entre nós distribuídos (inclusive através de redes públicas ou clouds distintas), o Vault embarca um motor completo de PKI X.509 (`vault/pki.py`).

### Autoridade Certificadora Raiz (Root CA)
* Chave RSA de 4096 bits autoassinada com extensões X.509 v3 (`basicConstraints=critical,CA:TRUE`, `keyCertSign`, `cRLSign`).
* Emitida automaticamente na inicialização (`vaultctl init`) ou carregada via PKI externa.

### Emissão de Certificados com SANs (IPs e DNS)
* Os certificados de nó contêm Subject Alternative Names (SANs) cobrindo tanto IPs quanto hostnames DNS (ex.: `127.0.0.1`, `10.10.20.10`, `vault-primary`, `vault.empresa.local`).
* Configurados com `extendedKeyUsage = serverAuth, clientAuth` para autenticação mútua bidirecional.

### mTLS Estrito no PostgreSQL (clientcert=verify-full)
A replicação de banco entre servidores exige certificados de cliente válidos assinados pela Root CA:
```text
hostssl replication replicator all cert clientcert=verify-full
```
* O nó Standby apresenta o certificado emitido para o usuário `CN=replicator`.
* Conexões sem SSL ou com certificados desconhecidos são **bloqueadas no handshake TLS**.

### Suporte a BYO-Cert (PKI Corporativa)
Empresas que utilizam Autoridades Certificadoras corporativas (Microsoft AD CS, DigiCert, Venafi, Let's Encrypt) podem injetar seus próprios certificados no bootstrapping:
```bash
vaultctl init --ca-cert /path/ca.crt --server-cert /path/server.crt --server-key /path/server.key
```

---

## 6. CLI Unificada (`vaultctl`)

A ferramenta de linha de comando `vaultctl` consolida todo o ciclo de vida operacional:

### `vaultctl init`
Inicializa as tabelas, configura o admin inicial, gera a `master.key` e emite os certificados da PKI interna:
```bash
vaultctl init \
  --admin-name admin \
  --admin-ip 10.10.20.37/32 \
  --output-dir ./vault-init-output \
  --node-san 10.10.20.10 \
  --node-san vault-primary
```

### `vaultctl seed standby`
Executado no nó Primário para emitir credenciais e certificados mTLS sob medida para uma réplica remota:
```bash
vaultctl seed standby 10.10.20.20 \
  --name vault-standby-1 \
  --primary-host 10.10.20.10 \
  --output ./node2.seed.tar
```
*Gera um pacote tar protegido contendo a `master.key`, o `ca.crt`, o par de chaves do nó Standby, o certificado de cliente do `replicator` e os metadados de conexão.*

### `vaultctl join`
Executado na VPS de destino para desempacotar o seed e configurar a conexão mTLS com o Líder:
```bash
vaultctl join --seed ./node2.seed.tar --output-dir ./vault-config
```

### `vaultctl promote`
Promove um nó Standby para Líder de escrita com checagem anti-split-brain:
```bash
vaultctl promote
# Forçar promoção em caso de isolamento de rede:
vaultctl promote --force
```

### `vaultctl rescue`
Executa extração forense de emergência (Break-Glass) diretamente da base de dados física:
```bash
vaultctl rescue --master-key ./master.key --output segredos.json
```

### `vaultctl certs inspect`
Inspeciona emissores, prazos de validade e SANs de qualquer certificado X.509:
```bash
vaultctl certs inspect ./vault-init-output/tls/server.crt
```

---

## 7. Guia de Deploy Passo a Passo

### Cenário A: Deploy Rápido em Host Único (`deploy.py`)

Ideal para desenvolvimento, testes locais ou appliances de nó único:

```bash
# 1. Execute o wizard interativo
python deploy.py

# 2. Parâmetros solicitados no terminal:
#    • Cluster com DR: s ou n
#    • Portas locais: ex: 8001 (Primário) e 8002 (Standby)
#    • IP permitido para o admin: ex: 10.10.20.37/32
#    • Senha mestra do admin
```
*O script detecta automaticamente portas livres no host, pula compilações se a imagem já existir e inicializa os containers.*

---

### Cenário B: Deploy Multi-VPS com Seeds (Estilo Conjur)

Para produção corporativa com isolamento físico real em VPSs ou nuvens separadas:

```text
[ VPS 1: 10.10.20.10 ]                      [ VPS 2: 10.10.20.20 ]
  (Primário Líder)                           (Standby DR Réplica)
         │                                              │
  1. vaultctl init                                      │
  2. vaultctl seed standby 10.10.20.20                  │
         │                                              │
         └─── scp node2.seed.tar ──────────────────────>│
                                                        │
                                                 3. vaultctl join --seed
                                                 4. docker run (Standby)
```

#### Passo 1: Na VPS Primária (`10.10.20.10`)
1. Inicialize o nó Líder:
   ```bash
   sudo docker run -d --name vault-primary \
     -p 8000:8000 \
     -p 5432:5432 \
     -v vault-primary-data:/var/lib/postgresql/data \
     vault
   ```
2. Execute a inicialização via `vaultctl`:
   ```bash
   sudo docker exec -it vault-primary vaultctl init \
     --admin-name admin \
     --admin-ip 10.10.20.0/24 \
     --node-san 10.10.20.10 \
     --output-dir /run/secrets/bootstrap
   ```
3. Gere o seed para a VPS 2:
   ```bash
   sudo docker exec -it vault-primary vaultctl seed standby 10.10.20.20 \
     --primary-host 10.10.20.10 \
     --key /run/secrets/bootstrap/master.key \
     --tls-dir /run/secrets/bootstrap/tls \
     --output /tmp/node2.seed.tar

   sudo docker cp vault-primary:/tmp/node2.seed.tar ./node2.seed.tar
   ```

#### Passo 2: Transferência Segura
Transfira o seed para a segunda máquina:
```bash
scp node2.seed.tar k8s@10.10.20.20:~/Vault/
```

#### Passo 3: Na VPS Standby (`10.10.20.20`)
1. Desempacote as configurações:
   ```bash
   python3 -m cli.vaultctl join --seed node2.seed.tar --output-dir ~/Vault/config
   ```
2. Inicialize o container Standby:
   ```bash
   sudo docker run -d --name vault-dr \
     -p 8000:8000 \
     -e REPLICATION_ROLE=standby \
     -e PRIMARY_HOST=10.10.20.10 \
     -e PRIMARY_PORT=5432 \
     --mount type=bind,source=/home/k8s/Vault/config/master.key,target=/run/secrets/master.key,readonly \
     --mount type=bind,source=/home/k8s/Vault/config/tls,target=/run/secrets/tls,readonly \
     -v vault-dr-data:/var/lib/postgresql/data \
     vault
   ```

---

### Distribuição Offline (Air-Gapped)

Para servidores sem acesso à internet externa:

1. **Na máquina de build (com internet):**
   ```bash
   docker build -t vault:latest .
   docker save -o vault.tar vault:latest
   ```
2. **Copia para o servidor:**
   ```bash
   scp vault.tar deploy.py usuario@servidor:~/
   ```
3. **No servidor de destino:**
   ```bash
   docker load -i vault.tar
   python3 deploy.py
   ```

---

## 8. Failover Manual e Proteção Anti-Split-Brain

Para evitar a partição de dados (*Split-Brain*) decorrente de dois nós acreditando serem masters em clusters de 2 nós:

```text
[ Operador executa Promoção ]
              │
              ▼
 Checagem Ativa: O Líder antigo ainda está respondendo?
       ├── SIM ──> [ BLOQUEADO - VLT-5003 ] Exige desligamento manual prévio.
       └── NÃO ──> [ PROMOÇÃO CONCLUÍDA ] O nó Standby assume escrita.
```

1. **Desligue o nó Primário anterior:**
   ```bash
   docker stop vault-primary
   ```
2. **Promova o nó Standby:**
   - **Pelo Host:**
     ```bash
     python deploy.py --promote vault-dr
     ```
   - **De dentro do Container:**
     ```bash
     docker exec -it vault-dr vaultctl promote
     ```
3. O status em `GET /health` converte-se instantaneamente para `{"role": "primary", "read_only": false}`.

---

## 9. Resgate de Emergência Offline (Break-Glass)

Garante acesso aos segredos mesmo se a API web for corrompida, travar ou for acidentalmente desinstalada.

```bash
# Extração em tela:
python deploy.py --rescue --key ./vault-init-output/master.key --volume vault-primary-data

# Exportação para arquivo JSON estruturado:
python deploy.py --rescue --key ./vault-init-output/master.key --volume vault-primary-data --output segredos.json
```

* **Com container online:** Executa extração em memória sem paradas.
* **Com container offline:** Sobe um container efêmero isolado (`--network none`), repara WALs se necessário via `pg_resetwal`, lê os dados utilizando a `master.key` e desliga imediatamente.

---

## 10. Referência Completa da API REST

### Autenticação & Sessão

#### `POST /auth/token`
Autentica uma integração via `app_name` e `app_secret`. Revalida a whitelist de IP do App ID.

* **Corpo:**
  ```json
  {"app_name": "app-backend", "app_secret": "chave-secreta"}
  ```
* **Resposta (`200 OK`):**
  ```json
  {"access_token": "eyJhbGci...", "token_type": "bearer", "expires_in": 900}
  ```

---

### Gestão de Segredos

#### `POST /secrets`
Cria um segredo no cofre indicado no path.

* **Headers:** `Authorization: Bearer <JWT>`
* **Corpo:**
  ```json
  {
    "name": "financeiro/chave-pix",
    "value": "valor-secreto-super-protegido",
    "permissions": [
      {"app_name": "app-pagamentos", "permissions": ["read"]}
    ]
  }
  ```
* **Resposta (`201 Created`):**
  ```json
  {"id": "c3a1b2d4-...", "name": "financeiro/chave-pix", "version": 1}
  ```

#### `GET /secrets/{name}`
Recupera o valor descriptografado de um segredo. Suporta busca por versão histórica.

* **Query Parameters:**
  - `version` (inteiro opcional, `1` a `2147483647`): Versão específica desejada.
* **Exemplo de busca por versão:**
  ```http
  GET /secrets/financeiro/chave-pix?version=2 HTTP/1.1
  Authorization: Bearer <JWT>
  ```
* **Resposta (`200 OK`):**
  ```json
  {
    "id": "c3a1b2d4-...",
    "name": "financeiro/chave-pix",
    "version": 2,
    "value": "valor-secreto-super-protegido"
  }
  ```

#### `PUT /secrets/{name}`
Rotaciona a DEK e atualiza o valor do segredo, incrementando a versão.

* **Corpo:**
  ```json
  {"value": "novo-valor-do-segredo"}
  ```
* **Resposta (`200 OK`):**
  ```json
  {"id": "c3a1b2d4-...", "name": "financeiro/chave-pix", "version": 3}
  ```

#### `DELETE /secrets/{name}`
Exclui permanentemente o segredo e todas as suas versões históricas. Resposta `204 No Content`.

---

### Gestão de Cofres (Vaults)

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/vaults` | Cria um novo cofre lógico |
| `GET` | `/vaults` | Lista todos os cofres acessíveis |
| `GET` | `/vaults/{name}/secrets` | Lista os segredos contidos no cofre |
| `POST` | `/vaults/{name}/permissions` | Concede ou substitui ACL em lote para o cofre |

---

### Gestão Administrativa & Auditoria

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/admin/apps` | Cria uma nova identidade de serviço (App ID) |
| `GET` | `/admin/apps` | Lista integrações cadastradas e seus IPs autorizados |
| `GET` | `/admin/audit` | Consulta a trilha de auditoria com paginação e filtros |
| `GET` | `/health` | Checagem de prontidão e papel do nó no cluster |

---

## 11. Dicionário de Códigos de Erro da Plataforma

Todas as falhas estruturadas de negócio retornam formato padronizado:
```json
{
  "detail": {
    "error_code": "VLT-XXXX",
    "message": "Descrição amigável da falha"
  }
}
```

| Código | Descrição Técnica | Código HTTP |
| :--- | :--- | :--- |
| **VLT-1001** | Master key ausente no caminho especificado em `MASTER_KEY_FILE` | 500 / Abort |
| **VLT-1002** | Master key inválida ou corrompida (tamanho incompatível com AES-256) | 500 / Abort |
| **VLT-1003** | Falha ao conectar ou provisionar schema no PostgreSQL | 500 / Abort |
| **VLT-1004** | Master key não confere com o verification blob salvo no banco | 500 / Abort |
| **VLT-1006** | Tentativa de reinicializar banco existente sem a flag `--force` | 400 |
| **VLT-2001** | Credenciais inválidas no login (`app_name` ou `app_secret` incorreto) | 401 |
| **VLT-2002** | IP do cliente fora da whitelist configurada no `allowed_ip` do App ID | 403 |
| **VLT-2003** | Token JWT ausente, corrompido ou expirado | 401 |
| **VLT-2004** | App ID já existe com o nome especificado | 409 |
| **VLT-2005** | App ID referenciado na concessão de ACL não foi localizado | 404 |
| **VLT-2006** | Renomeação de App ID desativada no servidor | 403 |
| **VLT-2007** | Rate limit de autenticação excedido (verifique header `Retry-After`) | 429 |
| **VLT-3001** | Segredo não localizado no cofre | 404 |
| **VLT-3002** | App ID sem a permissão necessária para a operação (ACL/RBAC) | 403 |
| **VLT-3003** | Segredo já existe com o nome especificado | 409 |
| **VLT-3004** | Versão solicitada do segredo não encontrada no histórico | 404 |
| **VLT-4001** | Cofre lógico não encontrado | 404 |
| **VLT-4002** | Cofre lógico já existente com o mesmo nome | 409 |
| **VLT-5001** | Nó em modo Standby (leitura restrita); escritas redirecionadas | 421 |
| **VLT-5002** | Falha durante execução de promoção de réplica | 500 |
| **VLT-5003** | Promoção bloqueada pela trava anti-split-brain (Líder ainda ativo) | 409 |
