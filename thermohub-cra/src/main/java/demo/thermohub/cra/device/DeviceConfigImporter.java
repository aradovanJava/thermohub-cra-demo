package demo.thermohub.cra.device;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.error.YAMLException;

import demo.thermohub.cra.common.InvalidInputException;

/**
 * A03:2025 Software Supply Chain Failures – fixed twice.
 * <ol>
 *   <li>Supply chain: SnakeYAML 2.x from the Spring Boot BOM (CVE-2022-1471 fixed), kept current by
 *       Dependabot and verified against the SBOM in CI.</li>
 *   <li>Code: {@link SafeConstructor} (standard YAML types only), size and alias limits, and an
 *       allowlist of setting names. Even a future parser bug meets a narrow input.</li>
 * </ol>
 */
public final class DeviceConfigImporter {

    private static final Set<String> ALLOWED_SETTINGS = Set.of("ecoMode", "displayBrightness", "schedule");
    private static final int MAX_CHARS = 4_096;

    public Map<String, Object> parse(String yaml) {
        if (yaml == null || yaml.isBlank() || yaml.length() > MAX_CHARS) {
            throw new InvalidInputException("Configuration must be 1-4096 characters of YAML");
        }
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(10);
        options.setCodePointLimit(MAX_CHARS);

        Object document;
        try {
            document = new Yaml(new SafeConstructor(options)).load(yaml);
        } catch (YAMLException e) {
            throw new InvalidInputException("Configuration is not valid ThermoHub YAML");
        }
        if (!(document instanceof Map<?, ?> map)) {
            throw new InvalidInputException("Configuration must be a mapping of settings");
        }
        Map<String, Object> settings = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            String key = String.valueOf(entry.getKey());
            if (!ALLOWED_SETTINGS.contains(key)) {
                throw new InvalidInputException("Unsupported setting");
            }
            settings.put(key, entry.getValue());
        }
        return settings;
    }
}
