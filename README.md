# 🔐 SecureVault - Password Manager

A full-stack **secure password manager** built using **Spring Boot, Thymeleaf, and H2 database**, designed to safely store and manage user credentials with strong encryption and authentication mechanisms.

---

## 🚀 Quick Start

### Prerequisites

* Java 17+
* Maven 3.6+

### ▶️ Run the Application

```bash
mvn spring-boot:run
```

Then open:
http://localhost:8080/auth/login

✔ No database setup required (H2 embedded)

---

## 🔑 User Setup

* Register a new account at `/auth/register`
* No default users are pre-configured

---

## 🏗️ Architecture

```
src/main/java/com/passmanager/
├── config/        # Spring Security configuration
├── controller/    # MVC Controllers
├── dto/           # Data Transfer Objects
├── entity/        # JPA Entities
├── repository/    # Data Access Layer
├── security/      # Authentication & Authorization
├── service/       # Business Logic
└── util/          # Utilities (Encryption, Generator)

src/main/resources/
├── templates/     # Thymeleaf UI
├── static/        # CSS & JS
```

---

## 🛡️ Security Features

| Feature            | Implementation               |
| ------------------ | ---------------------------- |
| Password Hashing   | BCrypt (strength 12)         |
| Vault Encryption   | AES-256-CBC + PBKDF2         |
| Session Management | 30 min timeout               |
| Two-Factor Auth    | TOTP-based                   |
| Security Questions | Hashed answers               |
| CSRF Protection    | Spring Security              |
| Re-authentication  | Required for password reveal |

---

## 🗄️ Database Design

* Users → Password Entries (1:N)
* Users → Security Questions (1:N)
* Users → Verification Codes (1:N)

H2 Console: http://localhost:8080/h2-console
JDBC URL: `jdbc:h2:mem:passmanagerdb`

---

## 📋 Features

* User Registration with Security Questions
* Secure Login (Username/Email)
* Password Vault (Add, Edit, Delete, View)
* Password Categories & Favorites
* Search & Filter
* Password Generator
* Strength Analyzer
* Security Audit (weak/reused passwords)
* Two-Factor Authentication (2FA)
* Profile Management
* Master Password Reset
* Encrypted Vault Export

---

## 🧪 Testing

```bash
mvn test
```

---

## 🛠 Tech Stack

* Java 17
* Spring Boot
* Spring Security
* Spring Data JPA
* Thymeleaf
* H2 Database
* BCrypt
* AES-256 Encryption
* Bootstrap
* Log4j2
* JUnit 5
* Maven

---

## 👨‍💻 Author

Rahul Kumar

---

## ⭐ Key Highlights (Interview Ready)

* Implemented **AES encryption + BCrypt hashing**
* Designed **secure authentication flow with 2FA**
* Built **role-based access & session management**
* Developed **end-to-end full-stack application**
