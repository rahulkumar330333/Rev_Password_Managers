package com.passmanager.security;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;

@Component
public class TOTPUtil {

    private static final Logger log = LoggerFactory.getLogger(TOTPUtil.class);

    public boolean verifyCode(String secret, String codeStr) {
        if (codeStr == null || codeStr.isBlank()) {
            return false;
        }
        try {
            // Aggressively clean input: remove all non-digits
            String cleanedCode = codeStr.replaceAll("\\D", "");
            if (cleanedCode.length() != 6) {
                log.warn("Invalid 2FA code length: {}", cleanedCode.length());
                return false;
            }
            int code = Integer.parseInt(cleanedCode);

            if (secret == null || secret.isBlank()) {
                return false;
            }
            // Aggressively clean secret: keep only valid Base32 characters A-Z, 2-7
            String cleanedSecret = secret.trim().toUpperCase().replaceAll("[^A-Z2-7]", "");

            // Add padding if missing (BouncyCastle can be strict)
            while (cleanedSecret.length() % 8 != 0) {
                cleanedSecret += "=";
            }

            long timeIndex = System.currentTimeMillis() / 1000 / 30;

            byte[] decodedSecret = Base32.decode(cleanedSecret);

            // Verify with a small tolerance window to account for minor clock drift
            boolean isValid = verify(decodedSecret, timeIndex, code);
            return isValid;
        } catch (Exception e) {
            log.debug("Error during 2FA verification: {}", e.getMessage());
            return false;
        }
    }

    private int getCodeForLogging(byte[] secret, long timeIndex) {
        try {
            return calculateCode(secret, timeIndex);
        } catch (Exception e) {
            return -1;
        }
    }

    private boolean verify(byte[] secret, long timeIndex, int code) {
        // Allow a small window of +/- 1 interval (30s each) for minor clock drift
        for (int i = -1; i <= 1; i++) {
            if (calculateCode(secret, timeIndex + i) == code) {
                return true;
            }
        }
        return false;
    }

    private int calculateCode(byte[] secret, long timeIndex) {
        byte[] data = ByteBuffer.allocate(8).putLong(timeIndex).array();
        HMac hmac = new HMac(new SHA1Digest());
        hmac.init(new KeyParameter(secret));
        hmac.update(data, 0, data.length);
        byte[] hash = new byte[hmac.getMacSize()];
        hmac.doFinal(hash, 0);

        int offset = hash[hash.length - 1] & 0xf;
        int truncatedHash = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        return (truncatedHash % 1000000);
    }
}
