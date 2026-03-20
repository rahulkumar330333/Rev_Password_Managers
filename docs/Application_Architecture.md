## Application Architecture

This diagram shows the high-level architecture for the password manager application.

```mermaid
flowchart LR
  User[User/Browser]
  CDN[CDN / Reverse Proxy]
  LB[Load Balancer]
  App[Spring Boot App (stateless, Docker/Container)]
  Worker[Background Worker / Scheduler]
  MySQL[(MySQL Primary)]
  Replica[(MySQL Replica)]
  Redis[(Redis Cache)]
  KV[Secrets Vault / KMS]
  Object[Object Storage (S3)]
  SMTP[SMTP / Email Service]
  CI[CI/CD (GitHub Actions)]
  Registry[Container Registry]

  User --> CDN --> LB --> App
  App -->|reads/writes| MySQL
  App -->|reads| Replica
  App --> Redis
  App --> KV
  App --> Object
  App --> SMTP
  App --> Worker
  Worker --> MySQL
  Worker --> SMTP
  CI --> Registry --> LB
  CI --> App

  classDef infra fill:#f8f9fa,stroke:#ccc,color:#111;
  class CDN,LB,MySQL,Replica,Redis,KV,Object,SMTP,Registry,CI infra;

```

Key points:
- **Stateless application**: The `App` runs in containers (Docker/K8s or App Service); horizontal scale via load balancer.
- **Persistent storage**: `MySQL` stores users, password entries (encrypted blobs), security questions, and verification codes. Use replicas for read-scaling and backups for recovery.
- **Encryption & secrets**: Application uses per-entry salt + AES-GCM; master keys and `app.encryption.secret` must be stored in a secrets vault or KMS (`KV`).
- **Caching**: `Redis` holds session data, rate-limiting counters, and short-lived caches (do not store secrets raw).
- **Background worker**: processes email sends, scheduled cleanup, verification code expiry, and long-running export tasks.
- **Object storage**: store exports or attachments encrypted server-side in `Object` (S3-compatible) with restricted access.
- **CI/CD**: build container images, run tests & security scans, push to a private container registry, deploy via pipeline.

Security notes:
- Move all secrets out of `application.properties` into environment variables and a secrets manager.
- Use TLS everywhere (LB/CDN -> App -> MySQL over private network).
- Enforce least privilege for database users; enable audit logging and backups.

If you'd like, I can also:
- generate an SVG/PNG image of this diagram and commit it to `docs/images/` (via `npx @mermaid-js/mermaid-cli`), or
- add a GitHub Action to auto-generate images on push.
