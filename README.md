# Weak-Cryptography
Weak cryptographic implementations to test tools 


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


Proceed to run the service through docker compose in detached mode: 

```
docker compose --profile dev-frontend up -d
```

If you want to stop the services: 

```
docker compose --profile dev-frontend down
```

Check which services are currently running: 

```
fotis@fotis-MS-7B86:~/Github/Weak-Cryptography$ docker compose ps
NAME                            IMAGE                                  COMMAND                  SERVICE     CREATED          STATUS                      PORTS
weak-cryptography-backend-1     ghcr.io/cbomkit/cbomkit:latest         "/opt/jboss/containe…"   backend     39 minutes ago   Up 39 minutes               8080/tcp, 8443/tcp, 0.0.0.0:8081->8081/tcp, [::]:8081->8081/tcp
weak-cryptography-db-1          docker.io/library/postgres:16-alpine   "docker-entrypoint.s…"   db          39 minutes ago   Up 39 minutes (unhealthy)   0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp
weak-cryptography-opa-local-1   docker.io/openpolicyagent/opa:1.15.1   "/opa run --server -…"   opa-local   39 minutes ago   Up 39 minutes               0.0.0.0:8181->8181/tcp, [::]:8181->8181/tcp
fotis@fotis-MS-7B86:~/Github/Weak-Cryptography$ 
```

I'm not sure why DB is unhealthy it seems to be working fine.


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