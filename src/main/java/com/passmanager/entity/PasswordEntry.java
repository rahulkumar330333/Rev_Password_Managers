package com.passmanager.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * PasswordEntry entity — Oracle-compatible.
 *
 * Oracle notes:
 *  - encryptedPassword / encryptedNotes use @Lob which maps to Oracle CLOB.
 *    This handles any size of AES-256 Base64-encoded data safely.
 *  - GenerationType.SEQUENCE is the correct Oracle strategy.
 *  - Enum stored as STRING (VARCHAR2 in Oracle).
 *  - passwordStrengthScore tracks 0-100 score for security audit.
 *  - lastAccessed tracks when entry was last decrypted.
 */
@Entity
@Table(name = "password_entries")
@SequenceGenerator(name = "pe_seq", sequenceName = "password_entries_seq", allocationSize = 1)
public class PasswordEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "pe_seq")
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 255)
    private String accountName;

    @Column(length = 500)
    private String websiteUrl;

    @Column(length = 255)
    private String usernameOrEmail;

    /**
     * AES-256 encrypted password stored as Base64.
     * Using @Lob maps to Oracle CLOB — handles all encryption output sizes.
     */
    @Lob
    @Column(nullable = false)
    private String encryptedPassword;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private Category category = Category.OTHER;

    /**
     * AES-256 encrypted notes — can be null.
     */
    @Lob
    @Column
    private String encryptedNotes;

    @Column(nullable = false)
    private boolean favorite = false;

    /** Strength score 0-100 calculated at save time for audit reports. */
    private Integer passwordStrengthScore;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt;

    /** Tracks last time password was decrypted/accessed. */
    private LocalDateTime lastAccessed;

    /** Transient — never persisted; set at request time after decryption. */
    @Transient
    private String decryptedPassword;

    public PasswordEntry() {}

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public enum Category {
        SOCIAL_MEDIA, BANKING, EMAIL, SHOPPING, WORK, OTHER
    }

    // ---- Getters and Setters ----

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }

    public String getAccountName() { return accountName; }
    public void setAccountName(String accountName) { this.accountName = accountName; }

    public String getWebsiteUrl() { return websiteUrl; }
    public void setWebsiteUrl(String websiteUrl) { this.websiteUrl = websiteUrl; }

    public String getUsernameOrEmail() { return usernameOrEmail; }
    public void setUsernameOrEmail(String usernameOrEmail) { this.usernameOrEmail = usernameOrEmail; }

    public String getEncryptedPassword() { return encryptedPassword; }
    public void setEncryptedPassword(String encryptedPassword) { this.encryptedPassword = encryptedPassword; }

    public Category getCategory() { return category; }
    public void setCategory(Category category) { this.category = category; }

    public String getEncryptedNotes() { return encryptedNotes; }
    public void setEncryptedNotes(String encryptedNotes) { this.encryptedNotes = encryptedNotes; }

    public boolean isFavorite() { return favorite; }
    public void setFavorite(boolean favorite) { this.favorite = favorite; }

    public Integer getPasswordStrengthScore() { return passwordStrengthScore; }
    public void setPasswordStrengthScore(Integer passwordStrengthScore) { this.passwordStrengthScore = passwordStrengthScore; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public LocalDateTime getLastAccessed() { return lastAccessed; }
    public void setLastAccessed(LocalDateTime lastAccessed) { this.lastAccessed = lastAccessed; }

    public String getDecryptedPassword() { return decryptedPassword; }
    public void setDecryptedPassword(String decryptedPassword) { this.decryptedPassword = decryptedPassword; }

    // ---- Builder ----
    public static PasswordEntryBuilder builder() { return new PasswordEntryBuilder(); }

    public static class PasswordEntryBuilder {
        private User user;
        private String accountName;
        private String websiteUrl;
        private String usernameOrEmail;
        private String encryptedPassword;
        private Category category = Category.OTHER;
        private String encryptedNotes;
        private boolean favorite = false;
        private Integer passwordStrengthScore;

        public PasswordEntryBuilder user(User user) { this.user = user; return this; }
        public PasswordEntryBuilder accountName(String v) { this.accountName = v; return this; }
        public PasswordEntryBuilder websiteUrl(String v) { this.websiteUrl = v; return this; }
        public PasswordEntryBuilder usernameOrEmail(String v) { this.usernameOrEmail = v; return this; }
        public PasswordEntryBuilder encryptedPassword(String v) { this.encryptedPassword = v; return this; }
        public PasswordEntryBuilder category(Category v) { this.category = v; return this; }
        public PasswordEntryBuilder encryptedNotes(String v) { this.encryptedNotes = v; return this; }
        public PasswordEntryBuilder favorite(boolean v) { this.favorite = v; return this; }
        public PasswordEntryBuilder passwordStrengthScore(Integer v) { this.passwordStrengthScore = v; return this; }

        public PasswordEntry build() {
            PasswordEntry e = new PasswordEntry();
            e.user = this.user;
            e.accountName = this.accountName;
            e.websiteUrl = this.websiteUrl;
            e.usernameOrEmail = this.usernameOrEmail;
            e.encryptedPassword = this.encryptedPassword;
            e.category = this.category;
            e.encryptedNotes = this.encryptedNotes;
            e.favorite = this.favorite;
            e.passwordStrengthScore = this.passwordStrengthScore;
            return e;
        }
    }
}
