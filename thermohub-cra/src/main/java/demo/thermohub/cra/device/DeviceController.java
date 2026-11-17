package demo.thermohub.cra.device;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import demo.thermohub.cra.audit.SecurityAuditLog;
import demo.thermohub.cra.audit.SecurityEventType;
import demo.thermohub.cra.crypto.SecureTokenGenerator;
import demo.thermohub.cra.crypto.WifiCredentialCipher;
import demo.thermohub.cra.device.Requests.CommandRequest;
import demo.thermohub.cra.device.Requests.PairRequest;
import demo.thermohub.cra.device.Requests.RenameRequest;
import demo.thermohub.cra.device.Requests.SetpointRequest;
import demo.thermohub.cra.device.Requests.WifiRequest;
import demo.thermohub.cra.security.Role;
import demo.thermohub.cra.web.RejectedRequestException;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/devices")
public class DeviceController {

    private final DeviceRepository devices;
    private final PairingService pairing;
    private final CommandPolicy commandPolicy;
    private final DeviceGateway gateway;
    private final DeviceConfigImporter configImporter;
    private final SecureTokenGenerator tokens;
    private final WifiCredentialCipher wifiCipher;
    private final SecurityAuditLog audit;

    public DeviceController(DeviceRepository devices, PairingService pairing, CommandPolicy commandPolicy,
                            DeviceGateway gateway, DeviceConfigImporter configImporter, SecureTokenGenerator tokens,
                            WifiCredentialCipher wifiCipher, SecurityAuditLog audit) {
        this.devices = devices;
        this.pairing = pairing;
        this.commandPolicy = commandPolicy;
        this.gateway = gateway;
        this.configImporter = configImporter;
        this.tokens = tokens;
        this.wifiCipher = wifiCipher;
        this.audit = audit;
    }

    @GetMapping
    public List<Device> myDevices(Authentication auth) {
        return devices.findByOwner(auth.getName());
    }

    /** A01 fix: ownership is part of the query; a foreign id is indistinguishable from a missing one. */
    @GetMapping("/{id}")
    public Device device(@PathVariable("id") long id, Authentication auth) {
        return owned(id, auth);
    }

    /** A05 fix: domain primitive + parameterised query. */
    @GetMapping("/search")
    public List<Device> search(@RequestParam("q") String q, Authentication auth) {
        return devices.search(auth.getName(), new SearchTerm(q));
    }

    /** A06 fix: the safe range is a domain invariant (Setpoint). */
    @PutMapping("/{id}/setpoint")
    public Device setpoint(@PathVariable("id") long id, @RequestBody SetpointRequest request, Authentication auth) {
        owned(id, auth);
        devices.updateSetpoint(id, auth.getName(), new Setpoint(request.celsius()));
        return owned(id, auth);
    }

    /** A09 fix: allowlisted characters only; nothing user-controlled is concatenated into logs. */
    @PutMapping("/{id}/name")
    public Device rename(@PathVariable("id") long id, @Valid @RequestBody RenameRequest request, Authentication auth) {
        owned(id, auth);
        devices.rename(id, auth.getName(), request.name());
        return owned(id, auth);
    }

    /** A06 fix: see PairingService. */
    @PostMapping("/pair")
    public Device pair(@Valid @RequestBody PairRequest request, Authentication auth) {
        return pairing.pair(request.serial(), request.code(), auth.getName());
    }

    /** A10 fix: parse once, decide on the typed value, fail closed, execute the same typed value. */
    @PostMapping("/{id}/commands")
    public ResponseEntity<Map<String, Object>> command(@PathVariable("id") long id, @Valid @RequestBody CommandRequest request,
                                                       Authentication auth) {
        Device device = owned(id, auth);
        Command command = Command.parse(request.command());
        if (commandPolicy.decide(rolesOf(auth), command) != CommandPolicy.Decision.PERMIT) {
            audit.record(SecurityEventType.COMMAND_DENIED, auth.getName(), device.serial() + " " + command);
            throw new RejectedRequestException(HttpStatus.FORBIDDEN, "Command not permitted");
        }
        String executed = gateway.send(device, command);
        return ResponseEntity.accepted().body(Map.of("device", device.serial(), "executed", executed));
    }

    /** A03 fix: patched parser from the BOM + SafeConstructor + allowlisted settings. */
    @PostMapping(value = "/{id}/config", consumes = {"application/yaml", "application/x-yaml", "text/plain"})
    public Map<String, Object> importConfig(@PathVariable("id") long id, @RequestBody String yaml, Authentication auth) {
        owned(id, auth);
        Map<String, Object> settings = configImporter.parse(yaml);
        return Map.of("device", id, "imported", settings.keySet());
    }

    /** A04 fix: CSPRNG token. */
    @PostMapping("/{id}/token")
    public Map<String, Object> issueToken(@PathVariable("id") long id, Authentication auth) {
        Device device = owned(id, auth);
        return Map.of("device", device.serial(), "apiToken", tokens.newApiToken());
    }

    /** A04 fix: AES-256-GCM with an injected key, bound to the device serial. */
    @PutMapping("/{id}/wifi")
    public Map<String, Object> storeWifi(@PathVariable("id") long id, @Valid @RequestBody WifiRequest request, Authentication auth) {
        Device device = owned(id, auth);
        devices.storeWifiSecret(id, auth.getName(), wifiCipher.encrypt(request.password(), device.serial()));
        return Map.of("device", id, "ssid", request.ssid(), "stored", "encrypted (AES-256-GCM)");
    }

    private Device owned(long id, Authentication auth) {
        return devices.findOwned(id, auth.getName()).orElseThrow(() -> {
            audit.record(SecurityEventType.ACCESS_DENIED, auth.getName(), "device " + id);
            return new RejectedRequestException(HttpStatus.NOT_FOUND, "Device not found");
        });
    }

    private static Set<Role> rolesOf(Authentication auth) {
        Set<Role> roles = EnumSet.noneOf(Role.class);
        for (GrantedAuthority authority : auth.getAuthorities()) {
            if ("ROLE_ADMIN".equals(authority.getAuthority())) {
                roles.add(Role.ADMIN);
            } else if ("ROLE_USER".equals(authority.getAuthority())) {
                roles.add(Role.USER);
            }
        }
        return roles;
    }
}
