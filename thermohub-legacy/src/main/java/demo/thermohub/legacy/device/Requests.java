package demo.thermohub.legacy.device;

import java.math.BigDecimal;

/** Request bodies. No validation anywhere – "the mobile app only sends sensible values". */
public final class Requests {

    private Requests() {
    }

    public record SetpointRequest(BigDecimal celsius) { }

    public record RenameRequest(String name) { }

    public record PairRequest(String serial, String code) { }

    public record CommandRequest(String command) { }

    public record WifiRequest(String ssid, String password) { }
}
