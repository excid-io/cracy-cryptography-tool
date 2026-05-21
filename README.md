
# Run the CBOM kit website 

Create a .env file that contains the following. Below are example values: 

```env
CBOMKIT_VERSION=latest
POSTGRESQL_AUTH_USERNAME=postgres
POSTGRESQL_AUTH_PASSWORD=postgres
CBOMKIT_VIEWER=false
VITE_CBOMKIT_HTTP_API_BASE=http://localhost:8081
VITE_POLICY_API_BASE=/opa
VITE_OPA_DECISION_PATH=/v1/data/cbom/eccg
VITE_SEMGREP_API_BASE=http://localhost:9091
```

## Start the frontend development stack

This starts the backend, database, frontend, and local OPA policy server.

```bash
docker compose --profile dev-frontend up -d
```

## Start the OPA policy server 

```bash
docker compose --profile policy up -d opa-local
```

## Recreate only the OPA policy server

Use this after changing Rego policy files under policies/eccg.

```bash
docker compose --profile policy up -d --force-recreate --no-deps opa-local
```

## Start only the Semgrep server
```bash
docker compose --profile semgrep up -d semgrep-local
```

## Recreate only the Semgrep server

Use this after changing the Semgrep server image or config.

```bash
docker compose --profile semgrep up -d --force-recreate --no-deps semgrep-local
```

## Query OPA directly with a CBOM file

OPA expects the CBOM to be wrapped under an input key.

```bash
jq '{input: .}' cbom.json | curl -s \
  -X POST http://localhost:8181/v1/data/cbom/eccg \
  -H 'Content-Type: application/json' \
  -d @- | jq
```

## Query a specific OPA policy package

Example for the RSA integer factorization policy:

```bash
jq '{input: .}' cbom.json | curl -s \
  -X POST http://localhost:8181/v1/data/cbom/eccg/asymmetric_atomic_primitives/rsa_integer_factorization \
  -H 'Content-Type: application/json' \
  -d @- | jq
```

Example for the AES modes policy:

```bash
jq '{input: .}' cbom.json | curl -s \
  -X POST http://localhost:8181/v1/data/cbom/eccg/symmetric_constructions/aes_modes \
  -H 'Content-Type: application/json' \
  -d @- | jq
```

## Check which services are currently running

```
docker compose ps
```

## Run the UI 

To run the vite site: 

```
npm install 
cd cbomkit-site
npm run dev
```

It should open the website at:

```
http://localhost:5173
```

Docker compose should have the following values: 

```yml
  backend:
    image: ghcr.io/cbomkit/cbomkit:${CBOMKIT_VERSION}
    depends_on:
      - db
    environment:
      CBOMKIT_DB_TYPE: postgresql
      CBOMKIT_DB_JDBC_URL: jdbc:postgresql://db:5432/postgres
      CBOMKIT_PORT: 8081
      CBOMKIT_DB_USERNAME: ${POSTGRESQL_AUTH_USERNAME}
      CBOMKIT_DB_PASSWORD: ${POSTGRESQL_AUTH_PASSWORD}
      #CBOMKIT_FRONTEND_URL_CORS: "http://localhost:8001"
      CBOMKIT_FRONTEND_URL_CORS: "http://localhost:5173"
      CBOMKIT_OPA_API_BASE: "http://opa:8181"
    ports:
      - "8081:8081"
    volumes:
      - cbomkit-volume:/home/user/.cbomkit
    restart: always
    deploy:
      resources:
        reservations:
          memory: 16g
    profiles:
      - prod
      - ext-compliance
      - dev-frontend
```

Ensure that `CBOMKIT_FRONTEND_URL_CORS` matches the local development URL used by `npm run dev`.

For example, if the frontend runs at:

```
http://localhost:5173
```

then the Docker Compose environment variable should be:

```
CBOMKIT_FRONTEND_URL_CORS: "http://localhost:5173"
```