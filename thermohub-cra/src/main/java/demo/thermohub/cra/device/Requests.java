package demo.thermohub.cra.device;

import java.math.BigDecimal;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request bodies with explicit, allowlist-style validation. Display names cannot contain control
 * characters, so they cannot forge log lines or break downstream systems (A09).
 */
public final class Requests {

    private Requests() {
    }

    public record SetpointRequest(BigDecimal celsius) { }

    public record RenameRequest(
            @NotBlank @Size(max = 40)
            @Pattern(regexp = "[\\p{L}\\p{N} ._-]+", message = "letters, digits, spaces, dots, dashes and underscores only")
            String name) { }

    public record PairRequest(
            @NotBlank @Pattern(regexp = "TH-\\d{4}") String serial,
            @NotBlank @Size(max = 16) String code) { }

    public record CommandRequest(@NotBlank @Size(max = 40) String command) { }

    public record WifiRequest(
            @NotBlank @Size(max = 32) String ssid,
            @NotBlank @Size(min = 8, max = 63) String password) { }
}
