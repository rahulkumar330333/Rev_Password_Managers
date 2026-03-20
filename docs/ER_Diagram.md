## ER Diagram

The following Mermaid ER diagram represents the canonical data model after cleaning duplicate source trees.

```mermaid
erDiagram
    USER {
      LONG id PK
      STRING username
      STRING email
      STRING password_hash
      STRING roles
      DATETIME created_at
    }

    PASSWORD_ENTRY {
      LONG id PK
      STRING title
      STRING username
      STRING encrypted_blob
      STRING url
      TEXT notes
      STRING category
      DATETIME created_at
      DATETIME updated_at
      LONG user_id FK
    }

    SECURITY_QUESTION {
      LONG id PK
      LONG user_id FK
      STRING question
      STRING answer_hash
    }

    VERIFICATION_CODE {
      LONG id PK
      LONG user_id FK
      STRING code
      STRING type
      DATETIME expires_at
      BOOLEAN used
    }

    USER ||--o{ PASSWORD_ENTRY : owns
    USER ||--o{ SECURITY_QUESTION : has
    USER ||--o{ VERIFICATION_CODE : receives

```

Notes:
- `PASSWORD_ENTRY.encrypted_blob` stores a per-entry salt (16B) and IV (12B) plus AES-GCM ciphertext (base64-encoded). The app derives the AES key using PBKDF2 with the per-entry salt and the user's master password.
- The canonical source tree is `src/` (top-level). Duplicate `password_manager/src/` was removed during cleanup.
- Production DB: MySQL (configured in `application.properties`); tests use H2 in-memory.

Save this file in the `docs/` folder and render with any Mermaid-compatible viewer (GitHub supports Mermaid in Markdown rendering).
