package demo.thermohub.cra;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import demo.thermohub.cra.firmware.FirmwareVerifier;
import demo.thermohub.cra.firmware.FirmwareVersion;

/** A08 – signed updates, anti-rollback, fail closed. Keys are generated per test run, none are committed. */
class FirmwareVerifierTest {

    private static final FirmwareVersion CURRENT = FirmwareVersion.parse("2.4.1");
    private static final FirmwareVersion NEXT = FirmwareVersion.parse("2.5.0");
    private static final byte[] IMAGE = "THERMOHUB-FW 2.5.0".getBytes(StandardCharsets.UTF_8);

    private KeyPair releaseKey;
    private FirmwareVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        releaseKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        verifier = FirmwareVerifier.fromBase64(Base64.getEncoder().encodeToString(releaseKey.getPublic().getEncoded()));
    }

    @Test
    @DisplayName("an image signed by the release pipeline is accepted")
    void signedImageIsAccepted() throws Exception {
        assertThat(verifier.verify(NEXT, IMAGE, sign(NEXT, IMAGE), CURRENT).accepted()).isTrue();
    }

    @Test
    @DisplayName("an unsigned image is rejected")
    void unsignedImageIsRejected() {
        assertThat(verifier.verify(NEXT, IMAGE, null, CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("one changed byte invalidates the signature")
    void tamperedImageIsRejected() throws Exception {
        String signature = sign(NEXT, IMAGE);
        byte[] tampered = IMAGE.clone();
        tampered[0] ^= 0x01;
        assertThat(verifier.verify(NEXT, tampered, signature, CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("the version is part of the signed manifest – relabelling is detected")
    void relabelledVersionIsRejected() throws Exception {
        assertThat(verifier.verify(FirmwareVersion.parse("3.0.0"), IMAGE, sign(NEXT, IMAGE), CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("a validly signed but older image is rejected (anti-rollback)")
    void rollbackIsRejected() throws Exception {
        FirmwareVersion old = FirmwareVersion.parse("2.3.9");
        assertThat(verifier.verify(old, IMAGE, sign(old, IMAGE), CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("an image signed with another key is rejected")
    void foreignKeyIsRejected() throws Exception {
        KeyPair attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(attacker.getPrivate());
        signer.update(FirmwareVerifier.manifest(NEXT.toString(), IMAGE));
        String forged = Base64.getEncoder().encodeToString(signer.sign());
        assertThat(verifier.verify(NEXT, IMAGE, forged, CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("garbage in the signature header fails closed")
    void malformedSignatureFailsClosed() {
        assertThat(verifier.verify(NEXT, IMAGE, "%%% not base64 %%%", CURRENT).accepted()).isFalse();
    }

    @Test
    @DisplayName("without a configured trust anchor every upload is rejected")
    void noTrustAnchorRejectsEverything() throws Exception {
        assertThat(FirmwareVerifier.fromBase64("").verify(NEXT, IMAGE, sign(NEXT, IMAGE), CURRENT).accepted()).isFalse();
    }

    private String sign(FirmwareVersion version, byte[] image) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(releaseKey.getPrivate());
        signer.update(FirmwareVerifier.manifest(version.toString(), image));
        return Base64.getEncoder().encodeToString(signer.sign());
    }
}
