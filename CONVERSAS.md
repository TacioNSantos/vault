# Conversas e decisões de arquitetura

## Criação de secrets e usuários de uma UI

**Pergunta:** Por que o exemplo de criação de secret no `/docs` pede um app e mostra `"create"` nas permissões?

**Resposta:** O app criador já é identificado pelo token Bearer. `permissions` é opcional: serve apenas para compartilhar o novo secret com outra integração. O criador recebe acesso automaticamente. `"create"` não é uma permissão individual de secret; pode ser concedida ao app de forma global ou a ele em um cofre específico.

Exemplo mínimo (o cofre `financeiro` precisa existir):

```json
{"name":"financeiro/minha-chave","value":"<valor-do-secret>"}
```

Exemplo com compartilhamento na criação:

```json
{
  "name": "financeiro/minha-chave",
  "value": "<valor-do-secret>",
  "permissions": [
    {"app_name": "app-leitora", "permissions": ["read"]}
  ]
}
```

**Pergunta:** E se um usuário humano criar um app ou administrar secrets por uma UI?

**Resposta:** Hoje o Vault identifica **apps/integrações**, não pessoas. Uma pessoa que usa uma UI não aparece automaticamente como autor das chamadas feitas pelo backend da UI. Criar integrações em `POST /admin/apps` requer uma identidade admin; o backend da UI precisa decidir quais usuários podem solicitar essa operação.

Abordagens discutidas:

1. **Backend da UI controla os usuários (recomendação inicial):** pessoas autenticam na UI; o backend verifica seus direitos e chama o Vault com uma identidade de serviço. O `app_secret` fica no servidor, nunca no navegador. O Vault audita a identidade da UI, e o backend precisa registrar qual pessoa iniciou cada ação.
2. **Vault conhece usuários e grupos:** integrar um IAM para o Vault autorizar e auditar cada pessoa diretamente. Exige ampliar os modelos, os tokens e as regras de acesso.
3. **Um App ID por pessoa:** aproveita a ACL existente, mas mistura usuários com integrações e aumenta a gestão de credenciais.

**Decisão em aberto:** escolher onde a autorização e a auditoria por pessoa devem ocorrer antes de implementar a UI. Conceder acesso à UI no Vault não substitui a verificação de permissões dos usuários humanos feita pelo backend na primeira abordagem.

## Alta Disponibilidade (DR / Standby) e Resgate de Emergência (Break-Glass)

**Pergunta:** Como implementar DR com replicação e failover manual, além de garantir acesso aos secrets se a aplicação estiver destruída?

**Decisão tomada:**
1. **Cluster 2 nós com Failover Manual:** Para evitar o risco de *Split-Brain* inerente a 2 nós sem quorum de maioria, o nó DR atua como *Hot Standby* assíncrono via streaming WAL do PostgreSQL.
   - `GET /health` responde `role: primary` ou `role: standby`.
   - O nó standby aceita leituras e rejeita escritas com `HTTP 421 Misdirected Request` (`VLT-5001`).
   - Promoção manual via `vaultctl role promote` (ou `vaultctl promote`).
   - **Trava Anti-Split-Brain:** O comando de promoção verifica ativamente se o nó primário ainda está online e respondendo como master. Se estiver, a promoção é rejeitada (`VLT-5003`) sem desligá-lo automaticamente, exigindo desligamento do primário antes de autorizar o DR a assumir.
2. **Break-Glass Híbrido (Online & Offline):**
   - Se o container estiver **online**, a extração ocorre em tempo real via `docker exec` no processo ativo, evitando conflito com o arquivo de lock `postmaster.pid` do PostgreSQL.
   - Se o container estiver **offline / morto**, sobe um container efêmero sem rede (`--network none`), monta o volume bruto e a `master.key`, limpa travas residuais, executa auto-recuperação de WAL se necessário (`pg_resetwal`) e extrai os segredos para terminal ou JSON.
