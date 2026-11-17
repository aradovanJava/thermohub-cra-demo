package demo.thermohub.legacy.device;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.yaml.snakeyaml.Yaml;

import demo.thermohub.legacy.crypto.LegacyApiTokenGenerator;
import demo.thermohub.legacy.crypto.LegacyWifiCipher;
import demo.thermohub.legacy.device.Requests.CommandRequest;
import demo.thermohub.legacy.device.Requests.PairRequest;
import demo.thermohub.legacy.device.Requests.RenameRequest;
import demo.thermohub.legacy.device.Requests.SetpointRequest;
import demo.thermohub.legacy.device.Requests.WifiRequest;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private static final Logger log = LoggerFactory.getLogger(DeviceController.class);

    private final DeviceRepository devices;
    private final CommandPolicy commandPolicy;
    private final DeviceGateway gateway;
    private final LegacyApiTokenGenerator tokens;
    private final LegacyWifiCipher wifiCipher;

    public DeviceController(DeviceRepository devices, CommandPolicy commandPolicy, DeviceGateway gateway,
                            LegacyApiTokenGenerator tokens, LegacyWifiCipher wifiCipher) {
        this.devices = devices;
        this.commandPolicy = commandPolicy;
        this.gateway = gateway;
        this.tokens = tokens;
        this.wifiCipher = wifiCipher;
    }

    @GetMapping
    public List<Device> myDevices(Authentication auth) {
        return devices.findByOwner(auth.getName());
    }

    /** A01:2025 Broken Access Control – IDOR: no ownership check. */
    @GetMapping("/{id}")
    public Device device(@PathVariable("id") long id) {
        return devices.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** A05:2025 Injection – see DeviceRepository.search. */
    @GetMapping("/search")
    public List<Device> search(@RequestParam("q") String q, Authentication auth) {
        return devices.search(auth.getName(), q);
    }

    /** A06:2025 Insecure Design – no physical safety limit on the setpoint. */
    @PutMapping("/{id}/setpoint")
    public Device setpoint(@PathVariable("id") long id, @RequestBody SetpointRequest request, Authentication auth) {
        owned(id, auth);
        devices.updateSetpoint(id, request.celsius());
        return owned(id, auth);
    }

    /** A09:2025 Logging & Alerting Failures – user input concatenated into the log (CRLF injection). */
    @PutMapping("/{id}/name")
    public Device rename(@PathVariable("id") long id, @RequestBody RenameRequest request, Authentication auth) {
        owned(id, auth);
        devices.rename(id, request.name());
        log.info("Device " + id + " renamed by " + auth.getName() + " to " + request.name());
        return owned(id, auth);
    }

    /** A06:2025 Insecure Design – unlimited guesses on a 4-digit pairing code. */
    @PostMapping("/pair")
    public ResponseEntity<Map<String, Object>> pair(@RequestBody PairRequest request, Authentication auth) {
        if (devices.pair(request.serial(), request.code(), auth.getName())) {
            return ResponseEntity.ok(Map.of("paired", request.serial(), "owner", auth.getName()));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "wrong pairing code"));
    }

    /** A10:2025 Mishandling of Exceptional Conditions – see CommandPolicy (fail-open). */
    @PostMapping("/{id}/commands")
    public ResponseEntity<Map<String, Object>> command(@PathVariable("id") long id, @RequestBody CommandRequest request,
                                                       Authentication auth) {
        Device device = owned(id, auth);
        String role = auth.getAuthorities().stream().anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority())) ? "ADMIN" : "USER";
        if (!commandPolicy.isAllowed(role, request.command())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "command not allowed for " + role));
        }
        String executed = gateway.send(device, request.command());
        return ResponseEntity.accepted().body(Map.of("device", device.serial(), "executed", executed));
    }

    /**
     * A03:2025 Software Supply Chain Failures – SnakeYAML 1.33 (CVE-2022-1471): the default
     * constructor instantiates any class named in a YAML tag.
     */
    @PostMapping(value = "/{id}/config", consumes = {"application/yaml", "application/x-yaml", "text/plain"})
    public Map<String, Object> importConfig(@PathVariable("id") long id, @RequestBody String yaml, Authentication auth) {
        owned(id, auth);
        Map<String, Object> settings = new Yaml().load(yaml);
        return Map.of("device", id, "imported", settings.keySet());
    }

    /** A04:2025 Cryptographic Failures – predictable token, see LegacyApiTokenGenerator. */
    @PostMapping("/{id}/token")
    public Map<String, Object> issueToken(@PathVariable("id") long id, Authentication auth) {
        Device device = owned(id, auth);
        return Map.of("device", device.serial(), "apiToken", tokens.newToken());
    }

    /** A04:2025 Cryptographic Failures – hard-coded key, ECB mode, see LegacyWifiCipher. */
    @PutMapping("/{id}/wifi")
    public Map<String, Object> storeWifi(@PathVariable("id") long id, @RequestBody WifiRequest request, Authentication auth) {
        owned(id, auth);
        String encrypted = wifiCipher.encrypt(request.password());
        devices.storeWifiSecret(id, encrypted);
        return Map.of("device", id, "ssid", request.ssid(), "stored", encrypted);
    }

    private Device owned(long id, Authentication auth) {
        return devices.findById(id)
                .filter(device -> auth.getName().equals(device.owner()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
