package demo.thermohub.cra.firmware;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * A08:2025 Software or Data Integrity Failures → CRA Annex I Part I (2)(f) and Part II (7).
 * <p>
 * A firmware image is accepted only if
 * <ol>
 *   <li>a trust anchor (Ed25519 public key of the release pipeline) is configured,</li>
 *   <li>the image carries a signature over the manifest {@code prefix | version | SHA-256(image)},</li>
 *   <li>the signature verifies, and</li>
 *   <li>the version is newer than what is rolled out (anti-rollback).</li>
 * </ol>
 * Any error on the way – bad Base64, unknown algorithm, malformed key – rejects. Fail closed.
 */
public final class FirmwareVerifier {

    public static final String MANIFEST_PREFIX = "thermohub-firmware-v1";

    private final PublicKey trustAnchor;

    public FirmwareVerifier(PublicKey trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    /** @param base64SubjectPublicKeyInfo X.509 SubjectPublicKeyInfo, Base64; blank means "no anchor" */
    public static FirmwareVerifier fromBase64(String base64SubjectPublicKeyInfo) {
        if (base64SubjectPublicKeyInfo == null || base64SubjectPublicKeyInfo.isBlank()) {
            return new FirmwareVerifier(null);
        }
        try {
            byte[] encoded = Base64.getDecoder().decode(base64SubjectPublicKeyInfo.strip());
            return new FirmwareVerifier(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded)));
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new IllegalStateException("THERMOHUB_FIRMWARE_PUBLIC_KEY is not a valid Ed25519 public key", e);
        }
    }

    public boolean hasTrustAnchor() {
        return trustAnchor != null;
    }

    /** The exact bytes the release pipeline signs. */
    public static byte[] manifest(String version, byte[] image) {
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
            return (MANIFEST_PREFIX + "\n" + version + "\n" + digest).getBytes(StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public Verdict verify(FirmwareVersion version, byte[] image, String base64Signature, FirmwareVersion rolledOut) {
        if (trustAnchor == null) {
            return Verdict.reject("No firmware signing key is configured – all uploads are rejected");
        }
        if (base64Signature == null || base64Signature.isBlank()) {
            return Verdict.reject("Firmware is not signed");
        }
        if (rolledOut != null && version.compareTo(rolledOut) <= 0) {
            return Verdict.reject("Rollback rejected: " + version + " is not newer than " + rolledOut);
        }
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(trustAnchor);
            verifier.update(manifest(version.toString(), image));
            boolean valid = verifier.verify(Base64.getDecoder().decode(base64Signature.strip()));
            return valid ? Verdict.accept() : Verdict.reject("Signature does not match the image");
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return Verdict.reject("Signature could not be verified");
        }
    }

    public record Verdict(boolean accepted, String reason) {

        static Verdict accept() {
            return new Verdict(true, "signature valid");
        }

        static Verdict reject(String reason) {
            return new Verdict(false, reason);
        }
    }
}
