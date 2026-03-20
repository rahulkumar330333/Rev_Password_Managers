package com.passmanager.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

@Component
public class EncryptionUtil {

    @Value("${app.encryption.secret}")
    private String encryptionSecret;

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";
    private static final int KEY_SIZE = 256; // bits
    private static final int ITERATION_COUNT = 65536;
    private static final int SALT_LENGTH = 16; // bytes
    private static final int IV_LENGTH = 12; // bytes, recommended for GCM
    private static final int TAG_LENGTH = 128; // bits for GCM

    private SecretKey deriveKey(String masterPassword, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(
                masterPassword.toCharArray(),
                salt,
                ITERATION_COUNT,
                KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), KEY_ALGORITHM);
    }

    public String encrypt(String plainText, String masterPassword) {
        try {
            SecureRandom rnd = new SecureRandom();
            byte[] salt = new byte[SALT_LENGTH];
            rnd.nextBytes(salt);
            byte[] iv = new byte[IV_LENGTH];
            rnd.nextBytes(iv);

            SecretKey key = deriveKey(masterPassword, salt);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
            byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[salt.length + iv.length + cipherText.length];
            System.arraycopy(salt, 0, combined, 0, salt.length);
            System.arraycopy(iv, 0, combined, salt.length, iv.length);
            System.arraycopy(cipherText, 0, combined, salt.length + iv.length, cipherText.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedText, String masterPassword) {
        try {
            byte[] combined = Base64.getDecoder().decode(encryptedText);
            if (combined.length < SALT_LENGTH + IV_LENGTH) {
                throw new IllegalArgumentException("Invalid encrypted data");
            }

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            byte[] cipherText = new byte[combined.length - SALT_LENGTH - IV_LENGTH];

            System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(combined, SALT_LENGTH, iv, 0, IV_LENGTH);
            System.arraycopy(combined, SALT_LENGTH + IV_LENGTH, cipherText, 0, cipherText.length);

            SecretKey key = deriveKey(masterPassword, salt);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            byte[] plain = cipher.doFinal(cipherText);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public String encrypt(String plainText) {
        if (encryptionSecret == null || encryptionSecret.isBlank()) {
            throw new IllegalStateException("app.encryption.secret property is required");
        }
        return encrypt(plainText, encryptionSecret);
    }

    public String decrypt(String encryptedText) {
        if (encryptionSecret == null || encryptionSecret.isBlank()) {
            throw new IllegalStateException("app.encryption.secret property is required");
        }
        return decrypt(encryptedText, encryptionSecret);
    }
}
