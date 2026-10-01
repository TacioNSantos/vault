# Principais riscos identificados

## 1. `trust_proxy` confia diretamente no `X-Forwarded-For`

**Problema:** quando `trust_proxy=true`, o Vault usa diretamente o primeiro IP enviado no header `X-Forwarded-For`. Se a API puder ser acessada sem passar pelo proxy esperado, esse IP pode ser falsificado.

**Possível solução:** criar uma lista de proxies confiáveis (`TRUSTED_PROXY_CIDRS`) e só aceitar `X-Forwarded-For` quando a conexão vier de um deles.

---

## 3. Quem possui `create` pode conceder acesso a terceiros

**Problema:** uma integração não-admin pode informar `permissions` durante o `POST /secrets` e conceder `read`, `update` ou `delete` para outro App ID.

**Possível solução:** permitir `permissions` na criação somente para admins ou criar uma permissão específica de delegação, como `grant`.

---

## 4. Dependências criptográficas/JWT antigas

**Problema:** o projeto usa versões antigas de `cryptography` e `python-jose`, incluindo versões com vulnerabilidades conhecidas.

**Possível solução:** atualizar as dependências, rodar a suíte de testes e manter monitoramento periódico de CVEs.

---

## 5. AES-GCM sem AAD

**Problema:** os ciphertexts e as DEKs criptografadas não estão vinculados criptograficamente ao UUID do secret, cofre ou versão.

**Possível solução:** usar AAD contendo, por exemplo:

```text
vault_id + secret_id + version
```

Assim, mover ciphertexts entre registros causa falha de autenticação.

---

## 6. Não existe rotação da Master Key (ME EXPLIQUE)

**Problema:** se a KEK precisar ser substituída, não existe atualmente um fluxo próprio para isso.

**Possível solução:** implementar versionamento da KEK e rewrapping das DEKs:

```text
KEK antiga → DEK → KEK nova
```

sem precisar recriptografar o valor de todos os secrets.

---

## 7. Master Key permanece disponível como arquivo montado

**Problema:** a `master.key` fica montada em `/run/secrets/master.key`. Um comprometimento privilegiado do host/container pode permitir sua leitura.

**Possível solução:** futuramente usar TPM, HSM, KMS ou `systemd-creds`, mantendo o arquivo apenas como modo de implantação simples.

---

## 8. PostgreSQL usa credencial fixa e usuário `SUPERUSER` [RESOLVIDO NO MONÓLITO]

**Status:** Implementado no monólito.
- Senha fixa removida do `Dockerfile` (eliminando o aviso de segurança do Docker build).
- Para clusters novos, uma senha aleatória de 32 bytes (`secrets.token_urlsafe(32)`) é gerada automaticamente e armazenada em `$PGDATA/.db_password` com permissões `0600`.
- O usuário da aplicação (`vault`) é configurado com `NOSUPERUSER NOCREATEDB NOCREATEROLE`, operando estritamente sob o Princípio do Menor Privilégio.
- No boot do container, privilégios `SUPERUSER` são automaticamente revogados mesmo em bancos pré-existentes.

---

## 9. PostgreSQL escuta em todas as interfaces [RESOLVIDO NO MONÓLITO / DR-READY]

**Status:** Implementado no monólito.
- Por padrão, o Postgres escuta estritamente em `localhost` (`listen_addresses='localhost'`). Como API e banco rodam no mesmo container, a comunicação é interna via loopback, impedindo qualquer acesso de rede externo à porta 5432.
- **Preparação para DR assíncrono futuro:** O parâmetro é configurável via variável de ambiente `POSTGRES_LISTEN_ADDRESSES`. No momento de configurar a réplica de DR, pode-se definir o IP da réplica ou `*` com regras restritas no `pg_hba.conf` para o usuário de replicação.

---

## 10. Possível enumeração de secrets

**Problema:** a API retorna `404` quando o secret não existe e `403` quando existe, mas o App ID não possui acesso.

**Possível solução:** para integrações sem acesso, responder `404` nos dois casos.

---

## 11. Falta limite de tamanho para secrets

**Problema:** não há limite explícito de tamanho para `value`, nomes ou corpo das requisições.

**Possível solução:** definir limites, por exemplo:

```text
Secret value: 64 KiB
Nome: 255 ou 512 caracteres
Request body: limite global
```

---

## 12. Exposição de documentação e schema OpenAPI (`/docs`, `/redoc`, `/openapi.json`) [RESOLVIDO]

**Status:** Implementado via middleware.
- Rotas `/docs`, `/redoc` e `/openapi.json` são interceptadas antes de serem processadas.
- Apenas conexões originadas do IP ou CIDR autorizado para usuários admin (`is_admin=True, active=True`) conseguem visualizar a documentação e o schema da API.
- Qualquer requisição de IP não autorizado recebe **`404 Not Found`**, eliminando superfície de ataque, reconhecimento e enumeração por scanners externos.
- Opcionalmente, pode ser fixado via variável de ambiente `DOCS_ALLOWED_IP`.

---

## 13. Proteção de Chaves Privadas em Repouso e em Trânsito (*.key.enc e tmpfs) [RESOLVIDO]

**Status:** Implementado no modelo Conjur.
- Chaves privadas TLS (`cluster.key`, `ca.key`) **nunca** tocam o disco persistente em texto puro. São salvas como `*.key.enc` cifradas com a Master Key (AES-256-GCM).
- No boot do container, as chaves são decifradas exclusivamente para memória volátil (`tmpfs` em `/dev/shm/vault_tls`, modo `0600`).
- No encerramento do container, as chaves em memória são sobrescritas e destruídas (*shred* via trap `EXIT/TERM/INT`).
- Pacotes seed gerados para novos nós (`vaultctl seed standby`) contêm apenas chaves cifradas e **nunca incluem a master.key**. A `master.key` deve ser entregue por canal seguro separado pelo administrador.

---

## 14. Replicação Segura via mTLS com pg_ident (Sem Senha Padrão) [RESOLVIDO]

**Status:** Implementado no modelo Conjur.
- Eliminação total de senhas estáticas de replicação no `entrypoint.sh` ou `Dockerfile`.
- O streaming de replicação WAL exige **mTLS obrigatório** (`hostssl ... cert map=cluster_map clientcert=verify-full`).
- O PostgreSQL mapeia a identidade do certificado do cluster para o papel `replicator` via `pg_ident.conf`.
- Tentativas de conexão sem certificado válido emitido pela Root CA são rejeitadas sumariamente no handshake TLS.

# Prioridade sugerida

1. Corrigir `trust_proxy`.
2. Rever a semântica de `create`.
3. Impedir delegação de ACL por integração comum.
4. Atualizar dependências.
5. Adicionar AAD.
6. Reduzir privilégios do PostgreSQL.
7. Criar rotação da KEK.
8. Adicionar limites de tamanho.
9. Reduzir enumeração de recursos.
