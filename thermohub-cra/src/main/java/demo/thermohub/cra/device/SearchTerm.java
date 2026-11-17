package demo.thermohub.cra.device;

import java.util.regex.Pattern;

import demo.thermohub.cra.common.InvalidInputException;

/**
 * A05:2025 Injection – defence in depth. The query is parameterised anyway (DeviceRepository);
 * the domain primitive additionally rejects anything that is not a plausible device name and escapes
 * LIKE wildcards, so the search cannot be turned into a "return everything" query either.
 */
public record SearchTerm(String value) {

    private static final Pattern ALLOWED = Pattern.compile("[\\p{L}\\p{N} ._-]{1,40}");

    public SearchTerm {
        if (value == null || !ALLOWED.matcher(value).matches()) {
            throw new InvalidInputException("Search term must be 1-40 letters, digits, spaces, dots, dashes or underscores");
        }
    }

    /** Pattern for {@code LIKE ? ESCAPE '\'} – wildcards in the user's input are matched literally. */
    public String containsPattern() {
        String escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return "%" + escaped + "%";
    }
}
