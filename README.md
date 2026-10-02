# Vault — Manual de Arquitetura, Segurança e Operação Técnica

Cofre corporativo de segredos (*Secrets Manager appliance*) operando sob o modelo de governança e ciclo de vida do **CyberArk Conjur (`evoke`)**.

Possui arquitetura de criptografia de envelope (Envelope Encryption), banco de dados transacional embutido com suporte a replicação síncrona/assíncrona, motor de PKI interna (X.509 / mTLS mútuo com certificado único de cluster), controle de acesso granular baseado em papéis (RBAC/ACL) e trilha de auditoria imutável.

---

## Sumário

1. [Visão Geral e Arquitetura do Sistema](#1-visão-geral-e-arquitetura-do-sistema)
   - [Envelope Encryption (KEK e DEK)](#envelope-encryption-kek-e-dek)
   - [Identidades de Serviço (App IDs) e Sessões JWT](#identidades-de-serviço-app-ids-e-sessões-jwt)
   - [Modelo de Cofres Lógicos e RBAC](#modelo-de-cofres-lógicos-e-rbac)
2. [O Modelo Operacional Conjur (evoke)](#2-o-modelo-operacional-conjur-evoke)
   - [Estados do Container: Unconfigured vs Configured](#estados-do-container-unconfigured-vs-configured)
   - [Certificado Único de Cluster](#certificado-único-de-cluster)
   - [Chaves Cifradas em Repouso (*.key.enc) e tmpfs](#chaves-cifradas-em-repouso-keyenc-e-tmpfs)
3. [Topologia de Rede e Segurança Zero-Trust](#3-topologia-de-rede-e-segurança-zero-trust)
   - [Isolamento de Infraestrutura](#isolamento-de-infraestrutura)
   - [Proteção Ativa de Documentação (/docs, /openapi.json)](#proteção-ativa-de-documentação-docs-openapijson)
   - [mTLS Estrito no PostgreSQL (clientcert=verify-full)](#mtls-estrito-no-postgresql-clientcertverify-full)
4. [Versionamento Granular de Segredos](#4-versionamento-granular-de-segredos)
   - [Estrutura do Histórico Imutável](#estrutura-do-histórico-imutável)
   - [Consulta de Versões Específicas (?version=X)](#consulta-de-versões-específicas-versionx)
   - [Controles de Segurança do Parâmetro](#controles-de-segurança-do-parâmetro)
5. [Guia de Operação da CLI Unificada (vaultctl)](#5-guia-de-operação-da-cli-unificada-vaultctl)
   - [vaultctl configure primary](#vaultctl-configure-primary)
   - [vaultctl seed standby](#vaultctl-seed-standby)
   - [vaultctl unpack seed](#vaultctl-unpack-seed)
   - [vaultctl configure standby](#vaultctl-configure-standby)
   - [vaultctl ca issue](#vaultctl-ca-issue)
   - [vaultctl role promote](#vaultctl-role-promote)
   - [vaultctl status](#vaultctl-status)
   - [vaultctl certs inspect](#vaultctl-certs-inspect)
   - [vaultctl rescue](#vaultctl-rescue)
6. [Fluxo de Deploy Multi-Máquina (Passo a Passo)](#6-fluxo-de-deploy-multi-máquina-passo-a-passo)
   - [Cenário 1: Com PKI Interna (Certificados Autoassinados)](#cenário-1-com-pki-interna-certificados-autoassinados)
   - [Cenário 2: Com Certificados Próprios (BYO-Cert — PKI Corporativa)](#cenário-2-com-certificados-próprios-byo-cert--pki-corporativa)
7. [Failover Manual com Trava Anti-Split-Brain](#7-failover-manual-com-trava-anti-split-brain)
8. [Resgate de Emergência Offline (Break-Glass)](#8-resgate-de-emergência-offline-break-glass)
9. [Referência Completa da API REST](#9-referência-completa-da-api-rest)
10. [Dicionário de Códigos de Erro da Plataforma](#10-dicionário-de-códigos-de-erro-da-plataforma)

---

## 1. Visão Geral e Arquitetura do Sistema

O Vault é empacotado como um appliance em container contendo a API FastAPI e o banco de dados PostgreSQL:

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
1. **Master Key (KEK — Key Encryption Key):** Chave de 256 bits entregue ao cofre via montagem `:ro` em `/run/secrets/master.key`. Fica carregada **exclusivamente na memória volátil** (`MasterKeyHolder`). Nunca vai para o disco em texto claro nem é impressa em logs.
2. **DEK por Secret (Data Encryption Key):** Cada segredo e cada versão possuem uma chave DEK individual. O segredo é cifrado com a DEK via **AES-256-GCM**. A DEK é cifrada com a Master Key e persistida no banco. Atualizações rotacionam a DEK sem afetar outros segredos.

### Identidades de Serviço (App IDs) e Sessões JWT
* **Credencial:** Identificador (`app_name`) + segredo em alta entropia (`app_secret`), protegido por hash **bcrypt**.
* **Origem Restrita:** Cada App ID é associado a um IP ou bloco CIDR permitido (`allowed_ip`).
* **Sessão Efêmera:** `POST /auth/token` emite um JWT de curta duração (padrão: 15 minutos). O IP de origem do cliente é validado em todas as chamadas subsequentes com token Bearer.

### Modelo de Cofres Lógicos e RBAC
* **Vaults (Cofres):** Contêineres lógicos (ex.: `financeiro`, `infraestrutura`).
* **Secrets (Segredos):** Registros associados ao cofre (ex.: `financeiro/db-password`).
* **Permissões:** `create` (global ou no cofre), `read`, `update` e `delete` (por cofre ou individuais por secret).

---

## 2. O Modelo Operacional Conjur (`evoke`)

O projeto segue rigorosamente o modelo operacional corporativo do CyberArk Conjur:

### Estados do Container: Unconfigured vs Configured
* O container é inicializado **sem configuração prévia** e não encerra se não houver banco configurado.
* **Estado `unconfigured`:** O processo do container permanece vivo em espera passiva. PostgreSQL e Uvicorn ficam parados aguardando a CLI `vaultctl`.
* **Estado `configured`:** Após a execução de `vaultctl configure primary` ou `vaultctl configure standby`, o arquivo de estado `$PGDATA/cluster.json` é gravado no volume e o container assume seu papel definitivo automaticamente.
* **Compatibilidade Retroativa:** Volumes já inicializados em versões anteriores continuam iniciando normalmente sem reconfiguração.

### Certificado Único de Cluster
Assim como no Conjur Enterprise:
* O nó Líder e todos os nós Standby **compartilham um único certificado de cluster** (`cluster.crt` e `cluster.key`).
* O certificado possui ExtendedKeyUsage para **Server Authentication (`serverAuth`)** e **Client Authentication (`clientAuth`)**.
* O mesmo certificado atende:
  1. HTTPS da API REST (Uvicorn).
  2. TLS do servidor PostgreSQL.
  3. Cliente mTLS da replicação de banco de dados.
* O nó Standby **herda** o certificado e a chave do Líder via pacote seed; `seed standby` **não** emite certificados individuais por nó.

### Chaves Cifradas em Repouso (*.key.enc) e tmpfs
* A chave privada do cluster (`cluster.key.enc`) e a chave da Root CA (`ca.key.enc`) ficam gravadas em repouso **sempre cifradas com a Master Key** (AES-256-GCM).
* Durante o boot, as chaves são decifradas exclusivamente para a **memória volátil** (`tmpfs` em `/dev/shm/vault_tls`, permissão `0600`).
* No encerramento do container, uma rotina de trap sobrescreve e limpa as chaves em memória (*shred*).
* A `master.key` **nunca é incluída no pacote seed**. Ela é entregue à máquina de destino pelo administrador através de canal seguro e montada em `/run/secrets/master.key`.

---

## 3. Topologia de Rede e Segurança Zero-Trust

### Isolamento de Infraestrutura
* O PostgreSQL escuta em `localhost` para tráfego local da API.
* Em nós primários, a comunicação de replicação externa exige **mTLS obrigatório**:
  ```text
  hostssl replication replicator all cert map=cluster_map clientcert=verify-full
  ```
* O arquivo `pg_ident.conf` mapeia o Common Name do certificado de cluster para o papel `replicator`. Não há senha padrão de replicação nem conexões em texto claro.

### Proteção Ativa de Documentação (/docs, /openapi.json)
* As rotas `/docs`, `/redoc` e `/openapi.json` são protegidas por middleware.
* Somente conexões originadas do IP ou CIDR autorizado para identidades admin (`is_admin=True, active=True`) conseguem acessar o Swagger UI e o schema OpenAPI.
* **IPs não autorizados recebem `HTTP 404 Not Found`**, mascarando a existência da documentação para scanners de vulnerabilidade externos.

---

## 4. Versionamento Granular de Segredos

O Vault mantém um histórico imutável na tabela `secret_versions`:

```text
POST /secrets (versão 1 criada)
PUT /secrets  (versão 2 criada, nova DEK gerada)
PUT /secrets  (versão 3 criada, nova DEK gerada)
```

### Consulta de Versões Específicas (?version=X)
* **Consulta da versão atual:**
  ```http
  GET /secrets/financeiro/db-password
  Authorization: Bearer <TOKEN>
  ```
* **Consulta de versão histórica específica:**
  ```http
  GET /secrets/financeiro/db-password?version=2
  Authorization: Bearer <TOKEN>
  ```

### Controles de Segurança do Parâmetro
* **Validação de Limites Rígidos:** `ge=1` e `le=2147483647` (evita estouro do tipo `INTEGER` no PostgreSQL).
* **Fail-Closed RBAC:** O acesso é validado antes da consulta de versão. Clientes não autorizados recebem `403` sem conseguir descobrir quais versões existem.
* **Isolamento Anti-IDOR:** A consulta histórica é amarrada ao UUID interno do secret:
  ```python
  filter(SecretVersion.secret_id == secret.id, SecretVersion.version == version)
  ```
* **Auditoria Forense:** O evento de auditoria grava explicitamente a versão recuperada (`detail="version=2"`).

---

## 5. Guia de Operação da CLI Unificada (`vaultctl`)

A ferramenta `vaultctl` é o ponto único de controle do appliance:

### `vaultctl configure primary`
Configura o container como Líder (Primário).
```bash
docker exec -it vault vaultctl configure primary \
    --hostname vault.exemplo.com \
    --altname vault1.exemplo.com \
    --altname vault2.exemplo.com \
    --altname 10.10.20.10 \
    --altname 10.10.20.20 \
    --admin-ip 10.10.20.37/32
```
* **Modo BYO (Bring-Your-Own-Cert):** Passe `--cert /path/cluster.crt --key /path/cluster.key --ca /path/ca.crt`. O Vault valida automaticamente formato PEM, correspondência de chaves, cadeia X.509, cobertura de SANs e EKU `serverAuth+clientAuth`.

### `vaultctl seed standby`
Gera o pacote `.seed.tar` protegido para inicializar uma nova réplica Standby:
```bash
docker exec vault vaultctl seed standby vault2.exemplo.com --primary-host vault1.exemplo.com > standby.seed.tar
```
*Contém certificados públicos, chaves privadas cifradas com a master key e metadados de replicação. A `master.key` **não** é incluída.*

### `vaultctl unpack seed`
Desempacota e valida o seed na máquina réplica (aceita arquivo ou stdin `-`):
```bash
docker exec -i vault vaultctl unpack seed - < standby.seed.tar
```
* **Nó virgem:** Desempacota os certificados e prepara o nó para o comando `vaultctl configure standby`.
* **Nó já configurado (atualização de certificados):** Atualiza imediatamente os certificados corporativos/SANs em `$PGDATA/tls`, decifra para `/dev/shm/vault_tls` e recarrega os serviços em tempo real, sem necessidade de re-sincronizar o banco de dados.

### `vaultctl configure standby`
Executado uma única vez na inicialização da réplica para sincronizar o banco inicial via `pg_basebackup -R` com mTLS `verify-full` e iniciar o streaming:
```bash
docker exec vault vaultctl configure standby
```
* **Re-sincronização:** Se desejar apagar o banco da réplica e forçar uma nova clonagem completa a partir do Líder, passe `--force`:
  ```bash
  docker exec vault vaultctl configure standby --force
  ```

### `vaultctl ca issue`
Reemite o certificado único de cluster adicionando novos SANs ou alterando o CN/hostname do cluster:
```bash
# Adicionar novos SANs mantendo os existentes:
docker exec -it vault vaultctl ca issue --force 10.10.40.112 vault3.empresa.local

# Alterar o CN e substituir a lista completa de SANs:
docker exec -it vault vaultctl ca issue --force \
    --hostname vault.empresa.local \
    --replace 10.10.40.107 10.10.40.112 vault.empresa.local vault1.empresa.local vault2.empresa.local
```
*Atualiza as chaves decifradas em memória (`tmpfs`), recarrega o PostgreSQL (`pg_ctl reload`) e o arquivo `cluster.json`. Em seguida, basta regenerar o seed para o nó Standby.*

### `vaultctl role promote`
Promove um nó Standby para Líder de escrita com verificação anti-split-brain via HTTPS:
```bash
docker exec -it vault vaultctl role promote
# Em caso de nó primário comprovadamente isolado:
docker exec -it vault vaultctl role promote --force
```

### `vaultctl status`
Exibe o papel do nó, FQDN, validade do certificado e status da replicação PostgreSQL:
```bash
docker exec -it vault vaultctl status
```

### `vaultctl certs inspect`
Inspeciona dados detalhados e validade de qualquer arquivo de certificado:
```bash
docker exec -it vault vaultctl certs inspect /var/lib/postgresql/data/tls/cluster.crt
```

### `vaultctl rescue`
Extrai segredos diretamente da base física em modo de emergência:
```bash
docker exec -it vault vaultctl rescue --master-key /run/secrets/master.key --output segredos.json
```

---

## 6. Fluxo de Deploy Multi-Máquina (Passo a Passo)

Demonstração prática de implantação em duas máquinas separadas (Líder em `10.10.20.10` e Standby em `10.10.20.20`).

```text
  [ NÓ 1 - 10.10.20.10 ]                                   [ NÓ 2 - 10.10.20.20 ]
            │                                                         │
 1. docker run (inicia unconfigured)                       1. docker run (inicia unconfigured)
 2. vaultctl configure primary                                        │
            │                                                         │
 3. vaultctl seed standby 10.10.20.20 ──── Pipe SSH ─────────────────>│
                                                           2. vaultctl unpack seed -
                                                           3. vaultctl configure standby
                                                                      │
                                                           4. mTLS WAL Streaming Ativo!
```

---

### Cenário 1: Com PKI Interna (Certificados Autoassinados)

O Vault cria automaticamente a sua própria Root CA de 4096 bits e emite o certificado do cluster com os SANs fornecidos.

#### Passo 1: Inicializar o Nó 1 (Líder / Primário)

1. Crie a `master.key` (chave aleatória de 32 bytes em base64):
   ```bash
   mkdir -p ./secrets
   python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())" > ./secrets/master.key
   chmod 600 ./secrets/master.key
   ```
2. Inicie o container (ele ficará em espera `unconfigured`):
   ```bash
   docker run -d --name vault \
       -p 443:443 \
       -p 5432:5432 \
       -v $(pwd)/secrets/master.key:/run/secrets/master.key:ro \
       -v vault-data:/var/lib/postgresql/data \
       vault:latest
   ```
3. Configure o Líder:
   ```bash
   docker exec -it vault vaultctl configure primary \
       --hostname vault.empresa.local \
       --altname vault1.empresa.local \
       --altname vault2.empresa.local \
       --altname 10.10.20.10 \
       --altname 10.10.20.20 \
       --admin-ip 10.10.20.0/24
   ```

#### Passo 2: Gerar Seed e Enviar ao Nó 2 (Standby)

1. Na Máquina 2, inicie o container com a **mesma master key** (entregue por canal seguro):
   ```bash
   # Na Máquina 2:
   docker run -d --name vault \
       -p 443:443 \
       -v $(pwd)/secrets/master.key:/run/secrets/master.key:ro \
       -v vault-data:/var/lib/postgresql/data \
       vault:latest
   ```

2. Na Máquina 1, gere o seed e envie via pipe SSH diretamente para o container do Nó 2:
   ```bash
   # Na Máquina 1:
   docker exec vault vaultctl seed standby 10.10.20.20 --primary-host 10.10.20.10 | \
       ssh usuario@10.10.20.20 "docker exec -i vault vaultctl unpack seed -"
   ```

#### Passo 3: Desempacotar e Conectar o Nó 2

Na Máquina 2, execute a configuração do Standby (nenhuma flag necessária; todos os parâmetros e certificados mTLS são herdados do seed):
```bash
# Na Máquina 2:
docker exec vault vaultctl configure standby
```
*O nó 2 executará o `pg_basebackup` via mTLS com o nó 1 e passará a receber o streaming de WAL em tempo real.*

---

### Cenário 2: Com Certificados Próprios (BYO-Cert — PKI Corporativa)

Se a sua organização já possui certificados emitidos por uma autoridade corporativa (Microsoft AD CS, DigiCert, Venafi, Let's Encrypt, etc.):

#### 1. Requisitos do Certificado Corporativo
* **Formato:** PEM em texto plano (ASCII com delimitadores `-----BEGIN CERTIFICATE-----` e `-----BEGIN RSA PRIVATE KEY-----` ou `PRIVATE KEY`).
* **Chave Privada:** Chave RSA sem senha (ela será cifrada em AES-256-GCM com a `master.key` pelo Vault ao ser importada).
* **ExtendedKeyUsage (EKU):** Deve conter obrigatoriamente:
  - `Server Authentication` (`serverAuth`, OID `1.3.6.1.5.5.7.3.1`)
  - `Client Authentication` (`clientAuth`, OID `1.3.6.1.5.5.7.3.2`) — *exigido para o mTLS da replicação.*
* **SANs (Subject Alternative Names):** Deve cobrir obrigatoriamente:
  - O FQDN ou hostname principal do cluster (ex.: `vault.empresa.com.br`)
  - O hostname ou IP da máquina Primária (ex.: `vault1.empresa.com.br`, `10.10.20.10`)
  - O hostname ou IP de **todas as máquinas Standby** (ex.: `vault2.empresa.com.br`, `10.10.20.20`)
  - `localhost` e `127.0.0.1`

---

#### 2. Estrutura de Pastas e Arquivos no Líder
Crie uma pasta dedicada para os certificados na máquina do Líder (ex.: `./certs`):
```text
/home/usuario/Vault/
├── certs/
│   ├── cluster.crt     # Certificado do cluster emitido pela sua PKI
│   ├── cluster.key     # Chave privada correspondente
│   └── ca.crt          # Root CA (ou cadeia de CAs intermediárias)
└── secrets/
    └── master.key      # Chave mestra do Vault (32 bytes em base64)
```

---

#### 3. Iniciar o Container do Líder montando os Certificados
Inicie o container montando a pasta de certificados no volume com `:ro`:
```bash
docker run -d --name vault \
    -p 443:443 \
    -p 5432:5432 \
    -v $(pwd)/secrets/master.key:/run/secrets/master.key:ro \
    -v $(pwd)/certs:/certs:ro \
    -v vault-data:/var/lib/postgresql/data \
    vault:latest
```

---

#### 4. Inicializar o Líder com as flags `--cert`, `--key` e `--ca`
Execute o `vaultctl configure primary` apontando os caminhos dos certificados montados:
```bash
docker exec -it vault vaultctl configure primary \
    --hostname vault.empresa.com.br \
    --altname vault1.empresa.com.br \
    --altname vault2.empresa.com.br \
    --altname 10.10.20.10 \
    --altname 10.10.20.20 \
    --admin-ip 10.10.20.0/24 \
    --cert /certs/cluster.crt \
    --key /certs/cluster.key \
    --ca /certs/ca.crt
```

**Validações automáticas de segurança executadas pelo `vaultctl`:**
1. Confirma se os PEMs são válidos e decodificáveis.
2. Compara a chave privada com a chave pública do certificado (rejeita se não baterem).
3. Valida se a cadeia do certificado confere criptograficamente com a CA fornecida.
4. Checa se o `--hostname` e todos os `--altname` estão presentes nos SANs do certificado.
5. Valida se possui EKU para `serverAuth` e `clientAuth`.
6. Verifica a data de validade (rejeita se expirado e avisa no terminal se restar menos de 30 dias).
7. Cifra a chave privada com a `master.key` em repouso (`cluster.key.enc`).

---

#### 5. Como o Nó Standby herda o Certificado Corporativo
Você **não precisa** copiar a pasta `certs/` para a segunda máquina!
O comando de seed empacota o certificado do cluster e a chave privada cifrada automaticamente:

```bash
# 1. Na Máquina 2: Inicie o container com a master.key montada
docker run -d --name vault \
    -p 443:443 \
    -v $(pwd)/secrets/master.key:/run/secrets/master.key:ro \
    -v vault-data:/var/lib/postgresql/data \
    vault:latest

# 2. Na Máquina 1: Gere o seed corporativo e envie via pipe SSH para a Máquina 2
docker exec vault vaultctl seed standby 10.10.20.20 --primary-host 10.10.20.10 | \
    ssh usuario@10.10.20.20 "docker exec -i vault vaultctl unpack seed -"

# 3. Na Máquina 2: Configure o Standby (herda certificados corporativos automaticamente)
docker exec vault vaultctl configure standby
```

---

#### 6. (Referência) Como gerar a CSR corporativa com OpenSSL
Se você precisar solicitar o certificado para a equipe de segurança da sua empresa:

1. Crie o arquivo `vault-csr.cnf`:
```ini
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = vault.empresa.com.br
O = Minha Empresa
OU = Seguranca

[req_ext]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature, keyEncipherment

[alt_names]
DNS.1 = vault.empresa.com.br
DNS.2 = vault1.empresa.com.br
DNS.3 = vault2.empresa.com.br
DNS.4 = localhost
IP.1 = 10.10.20.10
IP.2 = 10.10.20.20
IP.3 = 127.0.0.1
```

2. Gere a chave privada e a requisição (CSR):
```bash
openssl req -new -nodes -out cluster.csr -newkey rsa:2048 -keyout cluster.key -config vault-csr.cnf
```
3. Envie o `cluster.csr` para a sua PKI corporativa assinar e utilize os certificados resultantes no Passo 3 e 4.

---

## 7. Failover Manual com Trava Anti-Split-Brain

Para promover um nó Standby com segurança:

1. **Desligue o container do Líder anterior:**
   ```bash
   docker stop vault
   ```
2. **Execute a promoção no Standby:**
   ```bash
   docker exec -it vault vaultctl role promote
   ```
   *O comando executa checagem ativa contra o endpoint HTTPS do primário. Se o primário ainda estiver online e respondendo como master, a promoção é rejeitada (`VLT-5003`). Se o primário estiver desligado, a réplica assume a escrita (`role: primary`).*

---

## 8. Resgate de Emergência Offline (Break-Glass)

Caso a aplicação esteja quebrada ou indisponível, os segredos podem ser extraídos diretamente da base bruta:

```bash
./scripts/rescue.sh --key ./secrets/master.key --volume vault-data --output segredos.json
```

Ou diretamente via Docker isolado da rede:
```bash
docker run --rm \
    -v vault-data:/var/lib/postgresql/data \
    --mount type=bind,source=$(pwd)/secrets/master.key,target=/run/secrets/master.key,readonly \
    --network none \
    --entrypoint bash \
    vault:latest -c "
      export PATH=\$(pg_config --bindir):\$PATH
      chown -R postgres:postgres /var/lib/postgresql/data && chmod 700 /var/lib/postgresql/data
      rm -f /var/lib/postgresql/data/postmaster.pid
      export POSTGRES_PASSWORD=\$(cat /var/lib/postgresql/data/.db_password)
      export DATABASE_URL=postgresql+psycopg2://vault:\$POSTGRES_PASSWORD@localhost:5432/vault
      gosu postgres pg_ctl -D /var/lib/postgresql/data -o '-c listen_addresses=localhost' -w start
      vaultctl rescue --master-key /run/secrets/master.key --format json
      gosu postgres pg_ctl -D /var/lib/postgresql/data -m fast -w stop
    " > segredos.json
```

---

## 9. Referência Completa da API REST

### Autenticação & Sessão

#### `POST /auth/token`
Troca credenciais de App ID por um token JWT Bearer.
```json
// Request
{"app_name": "app-pagamentos", "app_secret": "chave-secreta"}

// Response (200 OK)
{"access_token": "eyJhbGciOi...", "token_type": "bearer", "expires_in": 900}
```

---

### Gestão de Segredos

#### `POST /secrets`
Cria um segredo no cofre indicado no nome.
```json
// Request
{
  "name": "financeiro/chave-pix",
  "value": "meu-segredo-super-protegido",
  "permissions": [
    {"app_name": "app-faturamento", "permissions": ["read"]}
  ]
}

// Response (201 Created)
{"id": "a1b2c3d4-...", "name": "financeiro/chave-pix", "version": 1}
```

#### `GET /secrets/{name}`
Recupera o valor descriptografado de um segredo. Suporta busca por versão histórica.
* **Query Parameters:** `version` (inteiro opcional, de `1` a `2147483647`).
```http
GET /secrets/financeiro/chave-pix?version=2
Authorization: Bearer <TOKEN>
```
```json
// Response (200 OK)
{
  "id": "a1b2c3d4-...",
  "name": "financeiro/chave-pix",
  "version": 2,
  "value": "meu-segredo-super-protegido"
}
```

#### `PUT /secrets/{name}`
Rotaciona a DEK e atualiza o valor do segredo, incrementando a versão e preservando histórico.
```json
// Request
{"value": "novo-valor-do-segredo"}

// Response (200 OK)
{"id": "a1b2c3d4-...", "name": "financeiro/chave-pix", "version": 3}
```

#### `DELETE /secrets/{name}`
Exclui permanentemente o segredo e todas as suas versões históricas (`204 No Content`).

---

### Gestão de Cofres (Vaults)

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/vaults` | Cria um novo cofre lógico |
| `GET` | `/vaults` | Lista todos os cofres acessíveis |
| `GET` | `/vaults/{name}/secrets` | Lista os segredos contidos no cofre |
| `POST` | `/vaults/{name}/permissions` | Concede ou substitui ACL em lote para o cofre |

---

### Gestão Administrativa & Monitoramento

| Método | Rota | Descrição |
| :--- | :--- | :--- |
| `POST` | `/admin/apps` | Registra nova identidade de serviço (App ID) com IP permitido |
| `GET` | `/admin/apps` | Lista identidades de serviço cadastradas e seus IPs autorizados |
| `GET` | `/admin/audit` | Consulta a trilha de auditoria com paginação e filtros |
| `GET` | `/health` | Checagem de prontidão e papel do nó no cluster (`role: primary` ou `role: standby`) |

---

## 10. Dicionário de Códigos de Erro da Plataforma

Todas as respostas de erro de negócio seguem o formato padronizado:
```json
{
  "detail": {
    "error_code": "VLT-XXXX",
    "message": "Descrição técnica do erro"
  }
}
```

| Código | Descrição Técnica | Código HTTP |
| :--- | :--- | :--- |
| **VLT-1001** | Master key ausente no caminho especificado em `MASTER_KEY_FILE` | 500 / Abort |
| **VLT-1002** | Master key inválida ou corrompida (tamanho incompatível com AES-256) | 500 / Abort |
| **VLT-1003** | Falha ao conectar ou inicializar banco PostgreSQL | 500 / Abort |
| **VLT-1004** | Falha na verificação de integridade da master key (não decifra blob ou chaves) | 500 / Abort |
| **VLT-1005** | Nó não configurado (execute `vaultctl configure primary` ou `configure standby`) | 500 / Abort |
| **VLT-1006** | Nó já configurado (reconfiguração bloqueada para proteger o banco) | 400 |
| **VLT-1007** | Pacote seed vazio, corrompido ou contendo `master.key` (violação de segurança) | 400 |
| **VLT-1008** | Componente obrigatório ausente no seed (`cluster.crt`, `cluster.key.enc`, etc.) | 400 |
| **VLT-1009** | Falha na validação de certificados BYO (chave incompatível, SAN ausente, EKU ou expirado) | 400 |
| **VLT-1010** | Chave da CA ausente (`ca.key.enc`). Reemissão requer PKI corporativa externa | 400 |
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
