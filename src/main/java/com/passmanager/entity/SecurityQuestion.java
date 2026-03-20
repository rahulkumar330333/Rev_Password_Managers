package com.passmanager.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * SecurityQuestion entity — Oracle-compatible.
 * Stores additional/overflow security questions beyond the 3 flat columns on User.
 * GenerationType.SEQUENCE is the canonical Oracle approach.
 */
@Entity
@Table(name = "security_questions")
@SequenceGenerator(name = "sq_seq", sequenceName = "security_questions_seq", allocationSize = 1)
public class SecurityQuestion {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sq_seq")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 500)
    private String question;

    @Column(nullable = false, length = 255)
    private String answerHash;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt;

    public SecurityQuestion() {}

    @PreUpdate
    public void preUpdate() { this.updatedAt = LocalDateTime.now(); }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    public String getQuestion() { return question; }
    public void setQuestion(String question) { this.question = question; }
    public String getAnswerHash() { return answerHash; }
    public void setAnswerHash(String answerHash) { this.answerHash = answerHash; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    // Builder
    public static SecurityQuestionBuilder builder() { return new SecurityQuestionBuilder(); }

    public static class SecurityQuestionBuilder {
        private User user;
        private String question;
        private String answerHash;

        public SecurityQuestionBuilder user(User user) { this.user = user; return this; }
        public SecurityQuestionBuilder question(String question) { this.question = question; return this; }
        public SecurityQuestionBuilder answerHash(String answerHash) { this.answerHash = answerHash; return this; }

        public SecurityQuestion build() {
            SecurityQuestion sq = new SecurityQuestion();
            sq.user = this.user;
            sq.question = this.question;
            sq.answerHash = this.answerHash;
            return sq;
        }
    }
}
