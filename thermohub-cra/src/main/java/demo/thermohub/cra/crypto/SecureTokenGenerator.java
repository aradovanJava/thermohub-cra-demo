package demo.thermohub.cra.crypto;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * A04:2025 fix – tokens and pairing codes come from a CSPRNG, never from {@link java.util.Random}.
 */
public final class SecureTokenGenerator {

    /** No 0/O, 1/I/L – codes are typed from a sticker on the device. */
    private static final char[] PAIRING_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789".toCharArray();

    private final SecureRandom random = new SecureRandom();

    /** 256-bit bearer token, URL-safe. */
    public String newApiToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Eight characters from a 31-symbol alphabet (about 40 bits), formatted XXXX-XXXX. */
    public String newPairingCode() {
        StringBuilder code = new StringBuilder(9);
        for (int i = 0; i < 8; i++) {
            if (i == 4) {
                code.append('-');
            }
            code.append(PAIRING_ALPHABET[random.nextInt(PAIRING_ALPHABET.length)]);
        }
        return code.toString();
    }
}
