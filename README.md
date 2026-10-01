# Vault

Cofre de secrets com possibilidade de integração futura com IAM. Envelope
encryption (master key -> DEK por secret), Postgres embutido, API REST,
JWT de curta duracao, ACL por App ID.

Este README é a referência do **comportamento implementado** para clientes e
outras IAs; [`CONVERSAS.md`](CONVERSAS.md) registra discussões de arquitetura.
Para obter o esquema HTTP gerado a partir dos tipos reais da API, consulte
`http://localhost:8000/openapi.json` (ou use `/docs` para testes interativos).

## Arquitetura

- **Master Key (KEK)**: gerada uma vez no `vault-init`, entregue ao admin
  como arquivo. Fica **somente em memoria** do processo em runtime. Nunca
  vai pro banco em claro, nunca eh logada.
- **DEK por secret**: cada secret tem sua propria Data Encryption Key,
  criptografada pela master key. O valor do secret eh criptografado pela
  DEK (AES-256-GCM), nao direto pela master key. Isso permite rotacionar
  o secret (nova DEK a cada update) sem tocar na master key.
- **App IDs**: cada integracao (app, admin, futura UI) eh um App ID com
  nome, IP/CIDR permitido, flag de `trust_proxy` (aceita
  `X-Forwarded-For`), e permissoes.
- **JWT**: integração troca `app_name` + `app_secret` por um JWT (15 min
  default) em `/auth/token`. Todas as chamadas subsequentes usam
  `Authorization: Bearer <token>`. IP eh revalidado em toda chamada, nao
  so no login.
- **Permissões**: `Permission.Create` pode ser global ou limitado a um cofre;
  `Permission.Read`, `Permission.Update` e `Permission.Delete` são concedidos
  por cofre ou por secret, via tabelas `vault_permissions` e
  `secret_permissions`.
- **Cofres**: entidades reais em `vaults`. Cada secret pertence a um cofre;
  `vault_permissions` concede operações sobre todos os secrets desse cofre.

## Topologia de Infraestrutura e Isolamento de Rede

O Vault adota um modelo de **perímetro estritamente fechado (Zero-Trust)**.
Ele não foi projetado para exposição pública nem para comunicação aberta na
rede. Toda a segurança de infraestrutura se baseia em três pilares:

```
[ Usuários / Navegadores ]
           │
           ▼  (Autenticação de usuários / IAM interno)
┌───────────────────────────────────────────────┐
│   Backend da UI / Gateway Autorizado          │
│   - IP fixo/conhecido (ex: 10.0.10.5)         │
│   - Guarda app_secret em segurança no servidor│
└───────────────────────┬───────────────────────┘
                        │
                        │ Rede Privada Isolada (Docker Network / VPC)
                        │ IP validado + JWT Bearer
                        ▼
┌───────────────────────────────────────────────┐
│              VAULT ISOLADO                    │
│   - allowed_ip restrito (ex: 10.0.10.5/32)    │
│   - API (8000) e Postgres (5432) internos     │
│   - Qualquer IP não autorizado -> 403 VLT-2002 │
│   - Ninguém sem permissão prévia conversa     │
└───────────────────────────────────────────────┘
```

### 1. Isolamento estrito de rede
- A instância do Vault (container contendo a API FastAPI e o PostgreSQL) deve
  permanecer em rede privada isolada (ex: Docker network interna sem mapeamento
  público de portas, ou subnet com Security Groups restritos).
- A porta da API (8000) e a do Postgres (5432) **nunca** devem ser expostas para
  a Internet pública ou redes abertas.
- Nenhuma entidade externa não autorizada consegue alcançar as portas do cofre.

### 2. Acesso apenas para integrações previamente configuradas
- O Vault **não responde a requisições arbitrárias**.
- Para que qualquer sistema converse com o Vault, ele precisa ter sido
  **previamente cadastrado por um admin** (`POST /admin/apps`) com:
  1. `app_name`: identificador único da integração.
  2. `allowed_ip`: IP exato (ou CIDR restrito) de onde as chamadas originam.
  3. `app_secret`: segredo gerado e armazenado de forma segura no cliente.
- **Validação de IP a cada requisição:** tanto no login (`/auth/token`) quanto em
  qualquer rota com Bearer token, o Vault valida se o IP de origem da conexão
  pertence ao `allowed_ip` do App ID.
- Se o IP não bater, a chamada é rejeitada imediatamente com **`403 Forbidden`**
  (`VLT-2002`) e o evento é registrado na auditoria como negado. Ter o token ou a
  senha não é suficiente: o IP também tem que ser o previamente liberado.

### 3. Modelo com UI de administração / Gateway
- Usuários humanos e navegadores **nunca conversam diretamente com o Vault**.
- A UI administrativa opera obrigatoriamente através de um **backend servidor
  dedicado**:
  - O backend da UI é registrado previamente no Vault como um App ID (ex.:
    `app_name: "ui-backend"` com `allowed_ip: "10.0.10.5"` correspondente ao IP da
    instância do backend).
  - O `app_secret` fica guardado **exclusivamente no servidor** da UI (em env var
    ou arquivo protegido), **nunca** exposto no frontend/navegador.
  - O backend da UI gerencia os logins humanos, permissões internas dos operadores
    e sessões de usuário.
  - Quando a UI precisa consultar ou alterar um secret ou cofre, seu backend
    efetua a chamada ao Vault a partir do seu IP autorizado, apresentando o JWT
    emitido para ele.
- Qualquer outra máquina, script ou usuário sem cadastro prévio e fora do IP
  autorizado é sumariamente bloqueado.

## Contrato atual para integrações e outras IAs

Esta seção descreve **o que o código faz hoje**, não uma proposta de arquitetura.
O README usa "instalação" para o conjunto banco PostgreSQL + `master.key` e
"cofre" para uma linha em `vaults` dentro dessa instalação. Um novo volume
Docker cria outra instalação; `POST /vaults` cria outro cofre **no mesmo banco**.

### Onde os dados ficam

| Tabela / arquivo | Dados e vínculos | Observações |
|---|---|---|
| `app_identities` | UUID interno, `name` único, hash bcrypt do `app_secret`, IP/CIDR permitido, `trust_proxy`, `is_admin`, `active`, permissão global de criar | `name` é `app_name` na API; o segredo puro nunca fica no banco |
| `vaults` | UUID interno e `name` único do cofre | Ex.: cofre `financeiro` |
| `secrets` | UUID interno, `vault_id`, `name` completo, `encrypted_dek`, `ciphertext`, `version`, `created_by`, datas | Ex.: `financeiro/producao/db-password` pertence ao cofre `financeiro` |
| `vault_permissions` | UUID do cofre + UUID do app + lista de permissões | Um grant vale para todos os secrets presentes e futuros do cofre |
| `secret_permissions` | UUID do secret + UUID do app + permissões de ler/alterar/excluir | ACL individual; o banco conserva colunas booleanas legadas, a API usa listas |
| `audit_log` | Data/hora UTC, ator, ação, recurso, resultado, IP e detalhe opcional | Metadados; não armazena valores de secrets, senhas ou tokens |
| `auth_rate_limits` | Contadores e início da janela de login por IP e por integração | Usado para responder `429`; compartilha estado entre processos |
| `vault_config` | Dados internos criptografados, incluindo chave de assinatura JWT e verificação da master key | Não contém a master key em claro |
| `master.key` | Chave mestra em arquivo montado no container | Fora do PostgreSQL; necessária junto com o volume para reiniciar |

O UUID é usado **internamente** para vincular apps, cofres, secrets, grants e
tokens. Um cliente usa **`app_name`** para identificar uma integração no login,
na concessão de acesso e na revogação. `app_id` **não é um campo de entrada da
API**. Para secrets, a API usa o `name` completo; a primeira parte antes de
`/` identifica o cofre. Segmentos posteriores organizam o nome, mas não criam
subcofres nem permissões intermediárias.

### Autenticação e respostas

`POST /auth/token` é público e aceita JSON:

```json
{"app_name":"app-financeiro","app_secret":"<credencial da integração>"}
```

Resposta `200` (valores ilustrativos):

```json
{"access_token":"<JWT>","token_type":"bearer","expires_in_seconds":900}
```

Use `Authorization: Bearer <JWT>` nas demais operações. A validade padrão é
15 minutos (`JWT_TTL_MINUTES`). Em cada chamada protegida, o servidor confere
assinatura e expiração, busca o App ID pelo UUID do token, verifica `active`,
IP de origem e as permissões **atuais no banco**. Revogar um app bloqueia até
tokens emitidos antes da revogação. `trust_proxy=false` por padrão; quando
ativado para um app, o IP autorizado vem do primeiro `X-Forwarded-For`. O IP
usado no **rate limit de login** é sempre o IP da conexão, sem confiar nesse
header. O `app_secret` de um novo app é retornado só na criação; não existe
endpoint para consultar o segredo puro depois.

### Endpoints disponíveis

Os corpos são JSON. `{name}` nos endpoints de secret aceita barras (é o nome
completo). `204` significa resposta **sem corpo**. `admin` significa um app
autenticado com `is_admin=true`.

| Método e rota | Acesso | Corpo principal | Resposta / efeito |
|---|---|---|---|
| `GET /health` | Público | — | `200 {"status":"ok"}` |
| `POST /auth/token` | Público; sujeito a rate limit | `app_name`, `app_secret` | `200`: JWT, tipo e duração |
| `POST /admin/apps` | Admin | `app_name`, `allowed_ip`, `permissions` globais (opcional), `trust_proxy` (opcional), `is_admin` (opcional) | `201`: `app_name`, `app_secret` gerado uma vez |
| `GET /admin/apps` | Admin | — | `200`: lista de apps, IP, permissões, `active`, `is_admin`, `trust_proxy`; **não** revela segredos |
| `DELETE /admin/apps/{app_name}` | Admin | — | `204`: desativa o app (`active=false`), sem apagar seus registros |
| `PATCH /admin/apps/{app_name}` | Admin, mas **desativado por padrão** | `new_app_name` | `403 VLT-2006`; apenas com `ENABLE_APP_RENAME=true` altera o nome |
| `POST /vaults` | Admin | `name` | `201`: nome do novo cofre |
| `GET /vaults` | App autenticado | — | `200`: cofres acessíveis (todos para admin ou app com `"create"` global) |
| `POST /vaults/{vault_name}/permissions` | Admin | `app_name`, `permissions` | `204`: substitui o grant desse app para **todo o cofre** |
| `GET /vaults/{vault_name}/permissions` | Admin | — | `200`: grants do cofre, com nomes dos apps e listas de permissões |
| `GET /vaults/{vault_name}/secrets` | App autenticado | — | `200`: `id`, `name`, `version` dos secrets que pode ler; admin vê todos |
| `POST /secrets` | Admin, `"create"` global ou `"create"` no cofre | `name`, `value`; `permissions` opcional | `201`: `id`, `name`, `version` do secret; criador recebe read/update/delete |
| `GET /secrets/{name}` | Admin ou app com `"read"` herdado/individual | `version` (query opcional) | `200`: `id`, `name`, `version`, **`value` em texto puro** (atual ou versão específica) |
| `PUT /secrets/{name}` | Admin ou app com `"update"` herdado/individual | `{"value":"<novo valor>"}` | `200`: `id`, `name`, `version` incrementada; cria nova versão no histórico |
| `DELETE /secrets/{name}` | Admin ou app com `"delete"` herdado/individual | — | `204`: exclui o secret |
| `POST /secrets/{name}/permissions` | Admin | `app_name`, `permissions` individuais | `204`: substitui o grant desse app somente nesse secret |
| `GET /admin/audit` | Admin | Filtros por query string | `200`: `items`, `total`, `limit`, `offset`; detalhes abaixo |

`permissions` globais em `/admin/apps` aceitam somente `"create"` (ou `[]`).
Permissões de cofre aceitam `"create"`, `"read"`, `"update"`, `"delete"`.
Permissões individuais de secret aceitam **apenas** `"read"`, `"update"` e
`"delete"`; `"create"` nesse corpo retorna erro de validação `422`. Campo
`permissions` omitido em `POST /secrets` significa **não compartilhar**. Se
omitido num grant de cofre/secret, vale `[]` e substitui o grant anterior. Os
grants herdados e individuais são somados: `[]` no secret **não bloqueia** um
acesso já concedido ao cofre. Mais detalhes na seção de RBAC abaixo.

### Respostas de erro e limites do modelo

Erros de negócio usam, em geral, `{"detail":{"error_code":"VLT-...","message":"..."}}`.
Falhas de validação de campos usam `422` do FastAPI/Pydantic e podem ter outro
formato de `detail`. Login inválido retorna `401`, token ausente/expirado
retorna `401`, IP ou permissão negada retorna `403`, recurso inexistente
retorna `404`, nome duplicado retorna `409`. Rate limit retorna `429`,
`VLT-2007` e o header `Retry-After` em segundos. Consulte a tabela de códigos
ao fim do documento para distinguir erros específicos.

**`version` não é histórico:** o `PUT` incrementa o contador e substitui o
`ciphertext` e a DEK. Hoje não é possível consultar ou restaurar versões
anteriores, inclusive as últimas 10 senhas. A auditoria registra **que** a
alteração ocorreu, não o valor anterior. Integração IAM, autorização e
auditoria de **usuários humanos** dentro do Vault também não foram
implementadas; atualmente os atores são App IDs (inclusive o backend de uma
eventual UI).

## Setup (primeira vez)

### Deploy interativo (Windows ou Linux)

Requer Python 3 e Docker em execução. Execute na pasta do projeto:

```text
python deploy.py
```

No Linux, use `python3 deploy.py` se o comando `python` não estiver disponível.
O script detecta o sistema, pergunta o nome do container, o volume do banco,
a porta, a pasta onde guardar `master.key`, o usuário,
o IP/CIDR permitido e a senha do admin (com confirmação). Ele constrói a
imagem, inicializa o banco apenas se não houver `master.key` na pasta escolhida
e inicia a API. Se o container já existir, oferece iniciá-lo caso esteja parado.
Use sempre o **mesmo volume e a mesma master key** ao subir a instalação.
Se o volume já tiver sido inicializado e a chave não estiver na pasta escolhida,
restaure a `master.key` original. Para começar um cofre independente do zero,
informe **outro nome de volume** no script. Ele não reinicializa volumes
existentes automaticamente.

Apenas `master.key` é gerada na pasta escolhida. O nome do admin (por padrão
`admin`) fica no banco, junto com o hash bcrypt da senha escolhida. Use esse nome
como `app_name` e a senha escolhida como `app_secret` em `POST /auth/token`.
Guarde a `master.key` em local privado; sem ela não é possível abrir os secrets
do banco. Não use `--force` no setup de um banco com secrets existentes.

### Implantação com Imagem Pronta (Sem compilar no servidor)

Você não precisa enviar o código-fonte para o servidor Linux de destino. É possível gerar a imagem em uma máquina e apenas exportá-la:

1. **Na máquina de desenvolvimento (gera o tar da imagem):**
   ```bash
   docker build -t vault:latest .
   docker save -o vault.tar vault:latest
   ```

2. **Copie apenas o `vault.tar` e o `deploy.py` para o servidor Linux:**
   ```bash
   scp vault.tar deploy.py usuario@ip-servidor:/home/usuario/
   ```

3. **No servidor Linux de destino:**
   ```bash
   docker load -i vault.tar
   python3 deploy.py
   ```
   *O `deploy.py` detecta automaticamente que a imagem já existe no Docker local e pula a etapa de compilação/build, indo direto para a configuração do Vault.*

   Também é possível especificar outra tag ou forçar build:
   - `python3 deploy.py --image meu-registro.com/vault:1.0`
   - `python3 deploy.py --build` (força a recompilação se o Dockerfile estiver presente)

### Comandos manuais

```bash
docker build -t vault .

# Inicia apenas o Postgres; usa o mesmo volume no setup e na API
docker run -d --name vault-setup -e VAULT_INIT_ONLY=1 \
    -v vault-data:/var/lib/postgresql/data vault

# Depois que o Postgres estiver pronto (o comando pedirá a senha do admin):
docker exec -it vault-setup vault-init init \
    --output-dir /tmp/vault-init-output \
    --admin-ip 10.0.0.5  # substitua pelo IP/CIDR autorizado do admin

mkdir -p ./vault-init-output
docker cp vault-setup:/tmp/vault-init-output/master.key ./vault-init-output/master.key
docker stop vault-setup
docker rm vault-setup
```

No setup manual, você escolhe a senha do admin no terminal. Isso gera:
- `vault-init-output/master.key` -> monte em `/run/secrets/master.key` no container real

No PowerShell, rode os mesmos comandos em uma linha cada, sem `\` no final:

```powershell
docker build -t vault .
docker run -d --name vault-setup -e VAULT_INIT_ONLY=1 -v vault-data:/var/lib/postgresql/data vault
docker exec -it vault-setup vault-init init --output-dir /tmp/vault-init-output --admin-ip 10.0.0.5
New-Item -ItemType Directory -Force -Path .\vault-init-output | Out-Null
docker cp vault-setup:/tmp/vault-init-output/master.key ./vault-init-output/master.key
docker stop vault-setup
docker rm vault-setup
docker run -d --name vault -p 8000:8000 -v "${PWD}/vault-init-output/master.key:/run/secrets/master.key:ro" -v vault-data:/var/lib/postgresql/data vault
docker logs vault
```

Substitua `10.0.0.5` pelo IP/CIDR de origem que o container deve aceitar para o admin.

## Rodando de verdade

```bash
docker run -d \
    -p 8000:8000 \
    -v $(pwd)/vault-init-output/master.key:/run/secrets/master.key:ro \
    -v vault-data:/var/lib/postgresql/data \
    --name vault \
    vault
```

Sem o `master.key` montado, o container **não sobe** — ver códigos de
erro abaixo.

### Configuração de runtime

| Variável de ambiente | Padrão | Uso |
|---|---|---|
| `MASTER_KEY_FILE` | `/run/secrets/master.key` | Local do arquivo de chave dentro do container |
| `DATABASE_URL` | Auto-detectado dinamicamente | Conexão do backend com o Postgres embutido |
| `POSTGRES_USER` | `vault` | Usuário da aplicação (operando como `NOSUPERUSER`) |
| `POSTGRES_PASSWORD` | Gerado aleatório / lido do volume | Senha do banco (não hardcoded na imagem) |
| `POSTGRES_LISTEN_ADDRESSES` | `localhost` | Interface onde o Postgres escuta (restrito ao container; configure para IP do DR no futuro) |
| `JWT_TTL_MINUTES` | `15` | Validade do token emitido no login |
| `AUTH_RATE_WINDOW_SECONDS` | `60` | Duração da janela do rate limit no login |
| `AUTH_RATE_LIMIT_IP` | `30` | Máximo de tentativas por IP de conexão na janela |
| `AUTH_RATE_LIMIT_APP` | `10` | Máximo de tentativas por integração existente na janela |
| `ENABLE_APP_RENAME` | `false` | Mantém `PATCH /admin/apps/{app_name}` bloqueado até ativação explícita |
| `VAULT_INIT_ONLY` | `0` | Com `1`, sobe apenas o Postgres para o `vault-init` |

Os três parâmetros de rate limiting devem ser inteiros positivos. O estado das
janelas é compartilhado via Postgres; elas incluem tentativas aceitas, negadas e
limitadas. Nomes de apps inexistentes contam apenas no limite por IP. O contador
recomeça quando expira a janela iniciada pela primeira tentativa daquela chave.
Reiniciar somente a API não apaga os contadores do volume.

## Fluxo de uso

### Testar a API pelo `/docs`

1. Abra `http://localhost:8000/docs` e execute `POST /auth/token` com
   `{"app_name":"admin","app_secret":"<senha escolhida no setup>"}`.
2. Copie **somente** o valor de `access_token` da resposta. Clique em
   **Authorize** no canto superior direito, cole o token no campo **HTTPBearer**
   (sem escrever `Bearer ` antes), confirme em **Authorize** e feche a janela.
3. Agora use **Try it out** nas rotas protegidas (`/vaults`, `/secrets`,
   `/admin/apps` etc.). O Swagger envia automaticamente o header
   `Authorization: Bearer <token>` em cada chamada. Quando expirar (15 minutos
   por padrão), obtenha outro token e atualize o **Authorize**.

O botão **Authorize** não copia sozinho o token retornado pelo login JSON: é
preciso colá-lo uma vez. Uma alternativa seria criar um fluxo OAuth2 com login
próprio para o Swagger, mas isso exigiria outra interface de login além do
`POST /auth/token` atual. Para usar `curl` ou outro cliente, continue enviando
o mesmo header `Authorization` diretamente.

O login tem rate limiting no PostgreSQL: por padrão, até **30 tentativas por
IP** e **10 por integração existente** a cada **60 segundos** (incluindo logins
bem-sucedidos). Ao exceder, responde `429` (`VLT-2007`) com `Retry-After` em
segundos e registra a recusa na auditoria. As janelas são compartilhadas mesmo
se houver mais de um processo de API; o limite por IP usa o endereço da conexão,
sem confiar em `X-Forwarded-For`. Ajuste com `AUTH_RATE_WINDOW_SECONDS`,
`AUTH_RATE_LIMIT_IP` e `AUTH_RATE_LIMIT_APP` (inteiros positivos) no container.

Para criar um usuário de integração, autentique-se como admin em `/auth/token`
e chame `POST /admin/apps`. Informe `app_name`, `allowed_ip` (IP/CIDR de origem da
integração) e, se ela precisar criar secrets, `permissions: ["create"]`. A
resposta devolve `app_name` e `app_secret` gerado automaticamente, **exibido uma
única vez**; o banco guarda somente seu hash. Para obter um token da integração,
use `app_name` e o `app_secret` retornado. Para ler secrets de outros usuários,
o admin precisa conceder acesso via `POST /secrets/{nome}/permissions` com o
`app_name` da integração e `permissions: ["read"]`.

```bash
# 1. autentica como admin, pega token
curl -X POST http://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"app_name": "admin", "app_secret": "<senha escolhida no setup>"}'

# 2. cria um App ID pra uma integracao real
curl -X POST http://localhost:8000/admin/apps \
    -H "Authorization: Bearer <token do admin>" \
    -H "Content-Type: application/json" \
    -d '{"app_name": "app-financeiro", "allowed_ip": "10.0.5.0/24", "permissions": []}'

# 3. admin cria o cofre (uma vez)
curl -X POST http://localhost:8000/vaults \
    -H "Authorization: Bearer <token do admin>" \
    -H "Content-Type: application/json" \
    -d '{"name": "app-financeiro"}'

# 4. admin libera criar e ler todos os secrets deste cofre
curl -X POST http://localhost:8000/vaults/app-financeiro/permissions \
    -H "Authorization: Bearer <token do admin>" \
    -H "Content-Type: application/json" \
    -d '{"app_name": "app-financeiro", "permissions": ["create", "read"]}'

# 5. app troca o nome + app_secret do passo 2 pelo seu token
curl -X POST http://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"app_name": "app-financeiro", "app_secret": "<app_secret recebido no passo 2>"}'

# 6. essa app cria um secret no cofre
curl -X POST http://localhost:8000/secrets \
    -H "Authorization: Bearer <token da app>" \
    -H "Content-Type: application/json" \
    -d '{"name": "app-financeiro/db-password", "value": "s3nh4-do-banco"}'

# 7. le o secret
curl http://localhost:8000/secrets/app-financeiro/db-password \
    -H "Authorization: Bearer <token da app>"
```

## Cofres reais e herança de acesso

`financeiro/producao/db-password` pertence ao cofre **`financeiro`**; o restante
é o caminho do secret dentro desse cofre. O cofre é uma linha na tabela `vaults`,
e cada linha em `secrets` aponta para ele por `vault_id` (UUID interno). Barras
após o primeiro segmento organizam nomes, mas não criam subcofres nem novas
regras de herança. Nomes de cofres são únicos, sem barras ou espaços. Esses
cofres compartilham o mesmo banco e `master.key` da instalação; um volume Docker
diferente cria outra instalação independente, não um cofre dentro da atual.

1. Um **admin** cria o cofre com `POST /vaults` e
   `{"name":"financeiro"}`. `GET /vaults` lista os cofres acessíveis ao app
   (todos para admins e apps com `"create"` global). Não é possível criar um
   secret em um cofre inexistente.
2. O admin cria uma integração em `POST /admin/apps` com
   `{"app_name":"leitor-financeiro","allowed_ip":"10.0.5.0/24"}`;
   por padrão, ela não tem acesso a nenhum cofre.
3. Para liberar **todo o cofre** em uma chamada, o admin usa
   `POST /vaults/financeiro/permissions`:

   ```json
   {"app_name":"leitor-financeiro","permissions":["read"]}
   ```

   A integração pode agora ler todos os secrets desse cofre, inclusive os
   criados no futuro, sem um grant por secret. `GET /vaults/financeiro/secrets`
   lista os secrets que ela pode ler. Se ela só tiver grants individuais,
   essa listagem mostrará apenas os secrets individuais legíveis. O admin pode
   conferir os grants do cofre em `GET /vaults/financeiro/permissions`.

As permissões no cofre aceitam `"create"`, `"read"`, `"update"` e `"delete"`.
`"create"` no cofre permite criar secrets **somente nele**; a permissão global
`"create"` do App ID permite criar em **qualquer cofre existente**. O admin
sempre pode fazer essas operações. Para leitores/escritores limitados a um
cofre, não dê a permissão global `"create"`.

**Regra de herança:** para cada operação, o acesso efetivo é o acesso do admin
**ou** a permissão global `"create"` (somente para criação) **ou** a permissão
do cofre **ou** uma permissão individual naquele secret. Um grant individual
`[]` não nega acesso herdado. Para remover um acesso herdado, substitua o grant
do cofre por outra lista (ou `[]`); grants individuais que existirem continuarão
valendo. Enviar a mesma lista novamente substitui os valores anteriores.

No primeiro boot da versão com cofres, secrets antigos são associados ao cofre
indicado pelo primeiro segmento do nome, criando-o automaticamente se preciso.
Secrets antigos sem `/` entram no cofre `default` e continuam acessíveis pelo
nome antigo. A migração conserva valores criptografados, grants individuais,
volume do banco e `master.key`; não execute `vault-init` novamente.

## Controle de acesso aos secrets (RBAC + ACL)

### Quem é o criador? E usuários de uma UI?

Em `POST /secrets`, o **criador é identificado pelo token Bearer**, não pelo
corpo da requisição. O corpo mínimo é
`{"name":"financeiro/minha-chave","value":"<valor>"}`; o cofre `financeiro`
precisa existir. `permissions` é opcional e só serve para compartilhar **esse
secret** na criação, por exemplo
`[{"app_name":"app-leitora","permissions":["read"]}]`. Não informe
`"create"` nessa lista: criação é uma permissão do cofre ou do App ID.

Atualmente, `app_identities` representa **integrações**, não usuários humanos.
Se uma pessoa usa uma UI, a API do Vault vê a identidade do **backend da UI**;
ela não sabe automaticamente qual usuário clicou no botão. Há três modelos:

| Modelo | Como funciona | Consequência |
|---|---|---|
| Backend da UI controla os usuários | UI autentica pessoas em IAM próprio; seu backend guarda `app_secret`, confere o acesso do usuário e chama o Vault com uma identidade de serviço | Mais simples; o Vault audita a identidade da UI, enquanto a UI deve auditar qual pessoa fez cada ação |
| Vault reconhece usuários/grupos | O Vault valida identidade do IAM e autoriza com grants de usuários/grupos, além dos grants de apps | RBAC e auditoria por pessoa no Vault; exige implementar essa integração e suas regras |
| Um App ID por pessoa | Cada pessoa recebe credenciais próprias do Vault | Usa ACL atual, mas aumenta a gestão de credenciais e mistura usuários com integrações |

Para a UI, a opção mais simples com o código atual é a primeira: **somente o
backend** guarda o `app_secret`; ele confere os direitos do usuário antes de
chamar o Vault. Não envie a credencial da UI ou de admin para o navegador. Se
precisar que o **próprio Vault** decida e audite por usuário humano, será
necessário implementar o segundo modelo. Criar apps via UI é tarefa de admin
na API (`POST /admin/apps`); no primeiro modelo, o backend da UI decide quais
usuários podem solicitar essa ação.

O Vault combina **papéis por integração** com **permissões individuais por
secret**. Cada integração (`app_identities`) tem um nome único (`app_name`) usado
na API, um UUID interno, um IP/CIDR permitido, `is_admin` e uma lista de
permissões globais. A tabela `secret_permissions` guarda, para cada par
**secret + UUID da integração**, as permissões daquele secret. A API recebe o
nome, procura a integração e grava a associação pelo UUID. O código usa o
enum `Permission.Create`, `Permission.Read`, `Permission.Update` e
`Permission.Delete`; na API, são strings minúsculas (`"create"`, `"read"`,
`"update"`, `"delete"`). Uma integração não recebe acesso a um secret só por
saber seu nome ou por ter `"create"`.

### Regras por operação

| Operação | Admin (`is_admin=true`) | Integração comum |
|---|---|---|
| Criar `POST /secrets` | Permitido em cofre existente | Exige `"create"` global ou no cofre |
| Ler `GET /secrets/{name}` | Permitido para qualquer secret | Exige `"read"` no cofre ou naquele secret |
| Alterar `PUT /secrets/{name}` | Permitido para qualquer secret | Exige `"update"` no cofre ou naquele secret |
| Excluir `DELETE /secrets/{name}` | Permitido para qualquer secret | Exige `"delete"` no cofre ou naquele secret |
| Listar `GET /vaults/{vault_name}/secrets` | Lista todos | Lista apenas os secrets legíveis |
| Criar cofre / conceder acesso no cofre | Permitido | Não permitido |
| Conceder/alterar permissões `POST /secrets/{name}/permissions` | Permitido | Não permitido, mesmo para o criador |
| Criar/listar/revogar integrações em `/admin/apps` | Permitido | Não permitido |

- `"create"` **global** para o App ID permite criar qualquer nome ainda não
  utilizado em um cofre existente. Para limitar a criação a `financeiro/`,
  conceda `"create"` **somente no cofre `financeiro`**.
  Por outro lado, não ter `"create"` não impede leitura ou alteração de
  secrets aos quais a integração recebeu acesso individual ou no cofre.
- O **criador** recebe automaticamente uma linha de permissão com
  `["read", "update", "delete"]` para o novo secret.
  Isso é uma ACL explícita, não um privilégio permanente de proprietário: um
  admin pode mudar esses três valores posteriormente.
- Ao criar um secret, quem tem permissão de criação pode opcionalmente passar
  `permissions` no corpo para compartilhar o **novo** secret com outros App IDs.
  Depois da criação, **somente um admin** pode mudar os grants. Um secret
  existente não herda permissões de outros secrets, mesmo que os nomes tenham
  o mesmo prefixo; o acesso comum a eles vem do grant no cofre.
- Um admin ignora as permissões por secret ao ler, alterar ou excluir, mas
  continua precisando de token válido e IP autorizado. A permissão de criação
  do admin não depende de `"create"`.
- Token JWT é obtido via `POST /auth/token` com `app_name` = **nome** e
  `app_secret` = segredo retornado na criação da integração (ou senha escolhida
  para o admin). Nas requisições seguintes, use `Authorization: Bearer <token>`.
  O token expira (15 minutos por padrão); a cada chamada o Vault consulta se
  a integração segue ativa, confere o IP e verifica a ACL atual. Revogar uma
  integração em `DELETE /admin/apps/{app_name}` a desativa, inclusive para tokens
  ainda não expirados.
- O IP comparado com `allowed_ip` é o IP de origem da requisição. Quando
  `trust_proxy=true`, o Vault usa o primeiro IP de `X-Forwarded-For`; por
  padrão, essa opção é `false`.

### Identificadores e corpo das permissões

`app_name` é o nome único da integração, usado no login, nos grants e na
revogação (por exemplo, `app-financeiro`). O UUID existe apenas no banco, nos
vínculos de ACL e nos tokens; não precisa ser informado na API. Nomes novos
devem começar com letra ou número e podem conter letras, números, `.`, `_` ou
`-` (sem espaços nem barras), pois também são usados em URLs. O endpoint de
grants recebe:

```json
{"app_name": "app-financeiro", "permissions": ["read"]}
```

`permissions` aceita `"read"`, `"update"` e `"delete"`; `"create"` só pode
ser informado em `/admin/apps`. A lista omitida equivale a `[]`. Se já existir
uma linha para esse par secret/integração, o endpoint **substitui a lista
inteira** pela enviada; por exemplo, enviar só `["read"]` remove as permissões
anteriores de alteração e exclusão. Enviar `[]` impede as três operações,
embora a linha de ACL continue no banco. Não há endpoint para listar as ACLs
de um secret ou removê-las fisicamente.

### Exemplo completo no PowerShell: integração apenas de leitura

Parta de um token de admin já obtido em `/auth/token` e substitua o IP/CIDR
de exemplo pelo IP de origem da integração. Use sempre `app_name` na API:

```powershell
$adminToken = '<JWT do admin>'
$headersAdmin = @{ Authorization = "Bearer $adminToken" }

# 1. Cria integração sem permissão global de criar secrets.
# Guarde app_secret da resposta: ele só é exibido uma vez.
$app = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/admin/apps' -Headers $headersAdmin -ContentType 'application/json' -Body (@{ app_name = 'app-financeiro'; allowed_ip = '10.0.5.0/24'; permissions = @() } | ConvertTo-Json)

# 2. Admin cria o cofre e o secret. Por padrão, apenas o criador e admins têm acesso.
$vault = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/vaults' -Headers $headersAdmin -ContentType 'application/json' -Body '{"name":"financeiro"}'
$secret = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/secrets' -Headers $headersAdmin -ContentType 'application/json' -Body (@{ name = 'financeiro/db-password'; value = 'senha-de-exemplo' } | ConvertTo-Json)

# 3. Admin libera SOMENTE leitura para o nome da integração.
Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/secrets/financeiro/db-password/permissions' -Headers $headersAdmin -ContentType 'application/json' -Body (@{ app_name = $app.app_name; permissions = @('read') } | ConvertTo-Json)

# 4. A integração autentica com o nome e o app_secret recebido no passo 1.
$authApp = Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/auth/token' -ContentType 'application/json' -Body (@{ app_name = $app.app_name; app_secret = $app.app_secret } | ConvertTo-Json)
Invoke-RestMethod -Method Get -Uri 'http://localhost:8000/secrets/financeiro/db-password' -Headers @{ Authorization = "Bearer $($authApp.access_token)" }
```

Se a integração precisar **alterar** esse secret, o admin pode repetir o passo
3 com `permissions = @('read', 'update')`. Para conceder acesso já na criação, inclua no
`POST /secrets` um array `permissions`, por exemplo
`[{"app_name":"app-financeiro","permissions":["read"]}]`. Cada entrada precisa
apontar para uma integração existente; evite repetir o mesmo nome ou incluir o
nome do próprio criador, que já recebe sua ACL automaticamente.
Para compartilhar **todos** os secrets do cofre em vez de apenas um, use
`POST /vaults/financeiro/permissions` com o mesmo `app_name` e a lista desejada.

`PATCH /admin/apps/{app_name}` aceita `{"new_app_name":"novo-nome"}` e foi
implementado, mas está **desativado por padrão** (`ENABLE_APP_RENAME=false`):
responde `403` (`VLT-2006`) sem alterar o banco. O UUID mantém grants e tokens
existentes válidos após uma renomeação, mas clientes que usam o nome antigo no
login ou em grants precisariam atualizar sua configuração. Para habilitar essa
rota, configure `ENABLE_APP_RENAME=true` no container ao criá-lo e coordene a
mudança com essas integrações.

Os valores são conjuntos na aplicação; o banco conserva as colunas booleanas
legadas para funcionar com volumes já inicializados. A API nova usa somente
listas `permissions`: chamadas antigas com `can_create_secrets`, `can_read`,
`can_update` ou `can_delete` devem ser atualizadas. Da mesma forma, a API agora
espera `app_name` no login, na criação, nos grants e em
`DELETE /admin/apps/{app_name}`; `app_id` (UUID) deixou de ser entrada pública.

**Erros típicos:** sem token ou com token inválido/expirado retorna `401`
(`VLT-2003`); credenciais inválidas no login retornam `401` (`VLT-2001`);
IP fora da allowlist retorna `403` (`VLT-2002`); falta de permissão retorna
`403` (`VLT-3002`); secret inexistente retorna `404` (`VLT-3001`).

## Auditoria para consultar em uma UI

O PostgreSQL guarda eventos em `audit_log`. Um admin pode consultá-los pelo
endpoint **`GET /admin/audit`**, usando seu token Bearer (também disponível no
`/docs`). A resposta tem `items`, `total`, `limit` e `offset`, com os eventos
mais recentes primeiro. Use `limit` (1 a 100; padrão 50) e `offset` para paginar.

Filtros opcionais: `app_name`, `action`, `result` (`success`, `denied` ou
`error`), `resource` (nome exato do secret/cofre/app), `since` e `until`
(data/hora ISO 8601 em UTC). Por exemplo:

```http
GET /admin/audit?app_name=app-financeiro&action=secret.read&result=denied&limit=20&offset=0
Authorization: Bearer <token do admin>
```

Formato da resposta `200` (dados fictícios; `timestamp` tem fuso UTC):

```json
{
  "items": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "timestamp": "2026-09-29T12:00:00+00:00",
      "app_name": "app-financeiro",
      "action": "secret.read",
      "resource": "financeiro/db-password",
      "result": "denied",
      "source_ip": "10.0.5.10",
      "detail": null
    }
  ],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

`app_name`, `action`, `resource` e `result` filtram por **igualdade exata**.
`since` é inclusivo e `until` é inclusivo; ambos aceitam ISO 8601 (por
exemplo, `2026-09-29T00:00:00Z`). Sem fuso informado, a data é tratada como
UTC. A ordenação é por `timestamp` decrescente e UUID do evento para desempate.
Para consultar a próxima página, aumente `offset` pelo número de itens
recebidos; uma nova ação durante a navegação pode alterar o deslocamento.

Um item tem `id`, `timestamp` (UTC), `app_name`, `action`, `resource`,
`result`, `source_ip` e `detail`. Logins aceitos ou negados (`auth.login`),
criação/leitura/alteração/exclusão de secrets, grants e criação/revogação de
apps/cofres já geram eventos. Leitura, alteração e exclusão de secrets sem
permissão também geram `denied`. O IP de login já era gravado; novos eventos
autenticados de alteração, leitura e grants também passam a registrar o IP
efetivo. Eventos antigos podem ter `source_ip: null`.

| `action` gerada hoje | Quando |
|---|---|
| `auth.login` | Login aceito, credenciais/IP negados ou rate limit atingido |
| `secret.create`, `secret.read`, `secret.update`, `secret.delete` | Operações em secrets; leitura/alteração/exclusão negadas por ACL também são registradas |
| `secret.permission_grant` | Admin altera grant individual de um secret |
| `vault.create`, `vault.permission_grant` | Admin cria cofre ou muda seu grant |
| `app.create`, `app.revoke`, `app.rename` | Admin cria, desativa ou, se a rota for habilitada, renomeia uma integração |

**Limites atuais:** nem toda tentativa com token inválido, erro de validação,
recurso inexistente ou operação de listagem gera evento. O log não contém
valores antigos dos secrets, senhas ou tokens e não substitui um histórico de
versões. `app_name` é resolvido a partir do UUID atual para eventos de apps
existentes; tentativas de login com credenciais inválidas conservam o nome
digitado. Se a ação veio de uma UI que usa uma identidade de serviço, o Vault
registra a **UI** como ator, não o usuário humano; o backend da UI precisa
registrar a identidade da pessoa ou integrar usuários ao Vault. Não há rotina
automática de retenção/limpeza de eventos nesta versão.

## Alta Disponibilidade (Cluster DR) & Failover Manual

O Vault suporta implantação em cluster com réplica assíncrona de **Disaster
Recovery (Hot Standby)** mantendo a arquitetura monólito em cada nó:

```
[ Cliente / UI Backend ]
        │
        ├──> (Escrita & Leitura) ──> [ Nó Primário :8000 ] (role: primary)
        │                                  │
        │                           PostgreSQL WAL Streaming
        │                                  ▼
        └─── (Somente Leitura)   ──> [ Nó DR Standby :8001 ] (role: standby)
```

### 1. Criando o Cluster via `deploy.py`

Execute o assistente interativo:

```powershell
python deploy.py
```

Responda `s` na pergunta:
`Deseja configurar Cluster com Réplica de DR (Hot Standby)? (s/N): s`

O script configura automaticamente:
1. Uma rede interna isolada do Docker (`vault-cluster-net`).
2. O nó **Primário** com usuário de replicação (`replicator`) e permissões no `pg_hba.conf`.
3. O nó **Standby (DR)** sincronizando o banco inicial via `pg_basebackup -R` e conectando ao streaming contínuo de WAL.
4. Compartilhamento seguro da `master.key` em modo `:ro` com ambos os nós.

### 2. Identificação do papel dos nós na rota `/health`

Qualquer nó do cluster expõe seu papel e prontidão em `GET /health` (público):

- **Nó Primário (`200 OK`):**
  ```json
  {"status": "ok", "role": "primary", "read_only": false}
  ```
- **Nó DR Standby (`200 OK`):**
  ```json
  {"status": "ok", "role": "standby", "read_only": true}
  ```

### 3. Comportamento do nó Standby
- **Leituras permitidas:** Aplicações podem autenticar (`POST /auth/token`) e ler secrets (`GET /secrets/{name}`) diretamente no nó de DR para distribuir consultas.
- **Escritas rejeitadas:** Qualquer tentativa de modificação (`POST /secrets`, `PUT`, `DELETE`, `/vaults`, `/admin`) no nó standby é bloqueada imediatamente com **`HTTP 421 Misdirected Request`** (`VLT-5001`), orientando o cliente a enviar a escrita para o primário.

### 4. Executando o Failover Manual (Promoção com Trava Anti-Split-Brain)

Para evitar **Split-Brain** (ter dois nós masters simultaneamente divergindo
dados), tanto o script de host quanto o comando interno realizam uma
**checagem ativa antes de promover**. Se o nó primário ainda estiver online e
respondendo como `primary`, a promoção é **bloqueada imediatamente** (`VLT-5003`).

O operador deve desligar o primário primeiro (`docker stop <primario>`) e em
seguida promover o DR:

**Opção A — Pela CLI do Host (de fora):**
```powershell
# 1. Garante que o primário antigo está desligado
docker stop vault-primary

# 2. Promove o nó DR a novo primário
python deploy.py --promote vault-dr
```

*(Em caso de partição de rede onde o primário está inacessível pelo host mas suspeita-se que esteja travado, pode-se passar `--force`: `python deploy.py --promote vault-dr --force`)*

**Opção B — De dentro do container DR:**
```bash
docker exec -it vault-dr vaultctl promote
```
*(Também suporta `vaultctl promote --force` se necessário)*

O comando valida a ausência do master ativo, aciona `pg_ctl promote`, encerra o estado de recuperação do PostgreSQL e converte a API para o papel de escrita (`read_only: false`). O `GET /health` passa a responder imediatamente `role: primary`.

---

### 5. Multi-VPS com mTLS e Seeds (Estilo CyberArk Conjur)

Para cenários onde os nós Primário e Standby (ou múltiplos Standbys) rodam em **VPSs ou servidores separados**:

A replicação PostgreSQL e a comunicação entre nós utilizam **mTLS (Mutual TLS)** obrigatório com verificação estrita de certificados (`clientcert=verify-full`), garantindo que o tráfego de replicação entre VPSs viaje 100% criptografado e imune a escutas ou conexões não autorizadas.

#### Passo 1: No nó Primário (VPS 1)
Gere o pacote seed exclusivo para o nó Standby informando o IP ou hostname da VPS remota:

```bash
docker exec -it vault-primary vaultctl seed standby 10.10.20.20 --primary-host 10.10.20.10 --output /tmp/node2.seed.tar
docker cp vault-primary:/tmp/node2.seed.tar ./node2.seed.tar
```
*O comando gera o certificado de nó para o IP do Standby, emite o certificado de cliente replicator mTLS assinado pela Root CA interna e empacota junto com a `master.key`.*

#### Passo 2: Copie o arquivo para a VPS Standby (VPS 2)
```bash
scp node2.seed.tar usuario@10.10.20.20:/home/usuario/
```

#### Passo 3: Na VPS Standby (VPS 2)
Desempacote e configure o nó:
```bash
python3 -m cli.vaultctl join --seed node2.seed.tar --output-dir ./vault-config
```
O comando exibe o `docker run` pronto para inicializar o nó Standby conectando via mTLS ao Primário.

#### Inspecionar Certificados X.509
Você pode inspecionar a validade e SANs de qualquer certificado a qualquer momento:
```bash
vaultctl certs inspect ./vault-init-output/tls/server.crt
```

---

## Resgate de Emergência (Break-Glass)

O comando `--rescue` garante a recuperação de **100% dos seus secrets** diretamente
do volume do banco e da `master.key`, funcionando de forma autônoma tanto com o
sistema online quanto com a aplicação completamente inoperante ou destruída:

```powershell
python deploy.py --rescue --key ./vault-init-output/master.key --volume vault-data
```

Para exportar diretamente para um arquivo JSON estruturado:

```powershell
python deploy.py --rescue --key ./vault-init-output/master.key --volume vault-data --output segredos-recuperados.json
```

### Como o resgate opera em cada cenário:

1. **Cenário Online (Container em execução):**
   - O `deploy.py` inspeciona os containers ativos no Docker e identifica se há
     algum nó utilizando o volume indicado.
   - Para evitar conflitos de trava de arquivos do PostgreSQL (`postmaster.pid`),
     ele aciona a ferramenta interna `vault-rescue` diretamente pelo processo
     ativo via `docker exec`.
   - A extração ocorre instantaneamente, em memória, **sem causar downtime nem
     reiniciar o container**.

2. **Cenário Offline (Container quebrado, parado ou excluído):**
   - O script detecta que nenhum container está usando o volume.
   - Sobe um container efêmero e completamente isolado da rede (`--network none`,
     sem portas expostas).
   - Monta o volume bruto do PostgreSQL e o arquivo `master.key` em modo somente leitura (`:ro`).
   - Remove travas de processos mortos (`postmaster.pid`) e auto-recupera o WAL se
     houve desligamento forçado ou corrupção de checkpoint (`pg_resetwal`).
   - Sobe o PostgreSQL em loopback interno, descriptografa as chaves DEK com a KEK
     da master key, extrai todos os segredos e desliga o banco de dados.
   - Exibe o relatório ou grava o JSON no disco e **destrói o container
     temporário imediatamente** (`--rm`).

---

## Códigos de erro

| Código | Significado |
|---|---|
| VLT-1001 | Arquivo de master key não encontrado no path esperado |
| VLT-1002 | Master key com formato ou tamanho inválido |
| VLT-1003 | Falha ao conectar no Postgres |
| VLT-1004 | Master key não confere com a usada no `vault-init` (verification blob falhou) |
| VLT-1005 | Vault nunca foi inicializado (rodar `vault-init init`) |
| VLT-1006 | `vault-init init` chamado de novo sem `--force` num vault já inicializado |
| VLT-2001 | App ID ou secret inválidos no login |
| VLT-2002 | IP de origem não autorizado para o App ID |
| VLT-2003 | Token JWT ausente, inválido ou expirado |
| VLT-2004 | App ID com esse nome já existe |
| VLT-2005 | App ID referenciado não encontrado |
| VLT-2006 | Renomeação de integração desativada |
| VLT-2007 | Limite de tentativas de login atingido (`429`; veja `Retry-After`) |
| VLT-3001 | Secret não encontrado |
| VLT-3002 | App ID sem a permissão necessária para a ação |
| VLT-3003 | Secret com esse nome já existe |
| VLT-4001 | Cofre não encontrado |
| VLT-4002 | Cofre com esse nome já existe |
| VLT-5001 | Nó em modo standby (somente leitura); escritas rejeitadas |
| VLT-5002 | Falha ao promover nó standby a primário |
| VLT-5003 | Promoção bloqueada por proteção anti-split-brain: nó primário ainda ativo/master |

## O que falta pra próxima fase (não é MVP escondido, é roadmap real)

- Rotação automática/agendada de secrets (hoje é manual via `PUT`)
- Proteção contra tentativas distribuídas de login em múltiplos IPs/contas
- Migrations versionadas (hoje `create_all` no `vault-init`, sem Alembic)
- Auto-unseal via TPM (`systemd-creds`) como alternativa ao arquivo `.key` puro
- Política de retenção e auditoria individual de usuários humanos em uma UI
