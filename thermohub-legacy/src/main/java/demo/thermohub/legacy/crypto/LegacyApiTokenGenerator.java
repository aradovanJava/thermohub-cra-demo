package demo.thermohub.legacy.crypto;

import java.util.HexFormat;
import java.util.Random;

import org.springframework.stereotype.Component;

/**
 * A04:2025 Cryptographic Failures – device API tokens from {@link java.util.Random}, seeded with
 * the clock. Knowing roughly when a token was issued is enough to regenerate it
 * (see CryptoExploitDemoTest).
 */
@Component
public class LegacyApiTokenGenerator {

    public String newToken() {
        return tokenFor(System.currentTimeMillis());
    }

    public static String tokenFor(long seed) {
        Random random = new Random(seed);
        byte[] token = new byte[16];
        random.nextBytes(token);
        return HexFormat.of().formatHex(token);
    }
}
