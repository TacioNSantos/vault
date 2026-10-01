FROM python:3.12-slim

# Postgres embutido no mesmo container (appliance monolitico, por escolha
# explicita). Em producao com escala considere separar em containers.
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql postgresql-contrib gosu \
    && rm -rf /var/lib/apt/lists/*

ENV POSTGRES_USER=vault
ENV POSTGRES_DB=vault
ENV PGDATA=/var/lib/postgresql/data
ENV PATH="/usr/lib/postgresql/17/bin:${PATH}"

WORKDIR /opt/vault

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY setup.py .
COPY cli ./cli
COPY vault ./vault
RUN pip install --no-cache-dir -e .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 443 5432
ENTRYPOINT ["/entrypoint.sh"]
