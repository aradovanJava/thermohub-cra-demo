import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Demo stand-in for the release pipeline's signing step (in CI this is a KMS/HSM key or Sigstore).
 * Single-file program, no build needed (Java 21):
 *
 *   java tools/FirmwareSigner.java keygen                       -> target/demo-keys/firmware-signing.key + public key
 *   java tools/FirmwareSigner.java image 2.5.0 fw-2.5.0.bin     -> writes a fake firmware image
 *   java tools/FirmwareSigner.java sign 2.5.0 fw-2.5.0.bin      -> prints the X-Firmware-Signature header
 *
 * The manifest format must match demo.thermohub.cra.firmware.FirmwareVerifier.
 */
public class FirmwareSigner {

    private static final String MANIFEST_PREFIX = "thermohub-firmware-v1";
    private static final Path DEFAULT_KEY = Path.of("target", "demo-keys", "firmware-signing.key");

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        switch (args[0]) {
            case "keygen" -> keygen(args.length > 1 ? Path.of(args[1]) : DEFAULT_KEY);
            case "image" -> image(args[1], Path.of(args[2]));
            case "sign" -> sign(args[1], Path.of(args[2]), args.length > 3 ? Path.of(args[3]) : DEFAULT_KEY);
            default -> usage();
        }
    }

    private static void keygen(Path keyFile) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.createDirectories(keyFile.toAbsolutePath().getParent());
        Files.writeString(keyFile, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        System.out.println("Private key written to " + keyFile.toAbsolutePath() + "  (never commit it)");
        System.out.println();
        System.out.println("Set this environment variable for the CRA app and restart it:");
        System.out.println("THERMOHUB_FIRMWARE_PUBLIC_KEY=" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    }

    private static void image(String version, Path file) throws Exception {
        Files.writeString(file, "THERMOHUB-FW " + version + "\n");
        System.out.println("Wrote demo firmware image " + file.toAbsolutePath());
    }

    private static void sign(String version, Path imageFile, Path keyFile) throws Exception {
        byte[] image = Files.readAllBytes(imageFile);
        PrivateKey key = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(Files.readString(keyFile).strip())));
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
        byte[] manifest = (MANIFEST_PREFIX + "\n" + version + "\n" + digest).getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(manifest);
        System.out.println("X-Firmware-Version: " + version);
        System.out.println("X-Firmware-Signature: " + Base64.getEncoder().encodeToString(signer.sign()));
    }

    private static void usage() {
        System.out.println("usage: java tools/FirmwareSigner.java keygen [keyfile]");
        System.out.println("       java tools/FirmwareSigner.java image <version> <file>");
        System.out.println("       java tools/FirmwareSigner.java sign <version> <image-file> [keyfile]");
    }
}
