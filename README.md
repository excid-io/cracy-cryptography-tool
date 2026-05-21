
# Overview 

This project is a web application for analyzing cryptographic usage in GitHub repositories using CBOMkit, OPA/Rego, and Semgrep.

The application accepts a GitHub repository URL and optional scan parameters, including a scan path, branch, commit SHA, and personal access token. The repository is scanned with CBOMkit to produce a Cryptography Bill of Materials (CBOM), which describes the cryptographic assets detected in the codebase.

The project then supports two evaluation paths:

1. **CBOM-based Rego evaluation**

   CBOMkit supports external compliance evaluation through Open Policy Agent (OPA), using user-defined policies written in Rego. This project follows that CBOMkit integration model and provides a custom Rego policy set for evaluating the generated CBOM.

   The Rego rules in this repository were written by us. They are based on our interpretation of the ENISA-published **ECCG Agreed Cryptographic Mechanisms, version 2** guidance, but they are not provided by ENISA and should not be treated as an official ENISA policy implementation.

2. **Source-level Semgrep evaluation**

   The project also includes custom Semgrep rules written by us. These rules scan the source code directly and are used to detect cryptographic API usage patterns that may or may not be fully represented in the CBOM.

Together, these two approaches provide complementary views of cryptographic usage. The Rego evaluation works from the CBOM produced by CBOMkit, while the Semgrep evaluation works directly on the repository source code.

## Motivation behind REGO evaluation 

As mentioned before this project uses Rego and Open Policy Agent (OPA) to evaluate cryptographic usage from CBOM data.

The decision to use Rego follows the compliance-evaluation model introduced in CBOMkit. In CBOMkit pull request [#332](https://github.com/cbomkit/cbomkit/pull/332), support was added for using OPA as an external compliance evaluation service. That PR describes OPA as a way to evaluate CBOM compliance using user-defined policies written in a declarative policy language, with the OPA instance and policy configuration made configurable by CBOMkit. This made Rego a natural choice for implementing our ECCG policy checks. :contentReference[oaicite:0]{index=0}

The Rego policies in this repository were created by us. They encode checks derived from our interpretation of the ENISA-published ECCG Agreed Cryptographic Mechanisms guidance. They are not official ENISA rules and should not be treated as an official ENISA policy implementation.

Rego provides several practical benefits for this project:

- **Policy as code:** cryptographic requirements can be written as version-controlled policy rules instead of being embedded directly in application logic.
- **CBOM-native evaluation:** Rego works well over structured JSON data, which makes it suitable for evaluating CycloneDX CBOM output.
- **Separation of concerns:** CBOMkit generates the CBOM, while OPA evaluates the CBOM against our ECCG policy. This keeps detection, policy, and UI concerns separate.
- **Easy CI/CD integration:** OPA and Rego can be run from command-line tooling, Docker containers, and CI environments such as GitHub Actions. This makes it straightforward to add CBOM policy checks to pull requests, release pipelines, or scheduled repository scans.
- **Portable policy execution:** the same Rego rules can be evaluated locally, in Docker Compose, in CI, or as part of a future CBOMkit integration.
- **Declarative rules:** Rego makes it easier to express compliance conditions such as “flag RSA modulus sizes below a threshold” or “detect non-agreed block ciphers” without writing custom imperative evaluation code for every check.
- **Explainable findings:** each rule can produce structured findings with rule IDs, severities, messages, notes, source references, and supporting metadata.
- **Extensibility:** new ECCG checks can be added incrementally as additional CBOM fields become available or as the policy coverage expands.

This work was also informed by conversations with the CBOMkit maintainers and developers. Because CBOMkit already supports configurable external compliance evaluation through OPA, the ECCG Rego policy developed in this project could be integrated into CBOMkit more easily in the future. The current implementation therefore follows the direction already established by CBOMkit: generate a CBOM, submit it to an OPA-compatible policy service, and return structured compliance findings.

The main limitation of the Rego-based evaluation is that it can only reason over the data that is present in the CBOM. If CBOMkit, or any other CBOM generator for that matter, does not detect a cryptographic operation, records it with incomplete metadata, or represents a field ambiguously, then the Rego policy cannot  always reliably evaluate it. For example, some rules that represent AES-128 depend on fields such as `parameterSetIdentifier`, but that value may not always represent the actual key size; it may instead reflect a block size, output size, or another algorithm parameter. Similarly, CBOM data may show that encryption and MAC operations exist in the same file, but it may not expose enough data-flow information to determine whether the code implements Encrypt-then-MAC, MAC-then-Encrypt, or Encrypt-and-MAC. Because of this, Rego evaluation is very useful for structured CBOM-level policy checks, but the quality of the results depends directly on the completeness and accuracy of the generated CBOM. Source-level tools such as Semgrep are still useful as a complementary evaluation method where CBOM metadata is incomplete or not expressive enough.

## Motivation behind Semgrep evaluation 

In addition to the CBOM-based Rego evaluation, this project also uses Semgrep to scan repository source code directly. The Semgrep rules were created standalone and then left to fill some of the gaps left by CBOM-level evaluation. While Rego is effective for evaluating structured CBOM data, it is limited by what CBOMkit detects and how much detail is represented in the generated CBOM. Semgrep provides a more source-aware evaluation path that can detect finer-grained implementation patterns, API usage, configuration choices, and insecure constructions that may not be fully captured in CBOM metadata.

Semgrep is especially useful for cases where the surrounding source context matters. For example, it can inspect how a cryptographic API is called, whether a constant IV is used, whether a TLS context allows legacy protocol versions, whether a particular mode is selected, or whether encryption and MAC operations are composed in a specific way. These details may be difficult or impossible to infer reliably from the CBOM alone, especially when the CBOM does not expose data-flow, operation ordering, or precise parameter semantics.

Another benefit of Semgrep is that it fits naturally into developer workflows. Rules can be run locally, in Docker, or in CI/CD systems such as GitHub Actions. Findings can point directly to source files and lines, making them easier for developers to inspect and fix. Semgrep rules are also version-controlled alongside the rest of the project, so the detection logic can evolve as new ECCG checks are implemented or as new cryptographic API patterns are identified.

However, Semgrep also has important limitations. The biggest downside is maintenance cost. Unlike Rego rules that operate over a normalized CBOM structure, Semgrep rules must often be written for specific programming languages, libraries, and API shapes. A rule that detects a pattern in Python’s `pyca/cryptography` library will not automatically detect the same concept in Java, Go, JavaScript, or C. Even within the same language, different coding styles, wrappers, helper functions, or framework abstractions may require additional rule variants.

Because of this, Semgrep evaluation can provide more detailed and fine-grained results, but it requires more ongoing work to keep the rule set accurate and useful. It is best used as a complementary source-level analysis layer alongside the Rego evaluation, rather than as a replacement for CBOM-based policy checks.


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