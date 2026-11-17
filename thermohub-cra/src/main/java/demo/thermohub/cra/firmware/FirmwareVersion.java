package demo.thermohub.cra.firmware;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import demo.thermohub.cra.common.InvalidInputException;

/** MAJOR.MINOR.PATCH, compared numerically – the basis for anti-rollback. */
public record FirmwareVersion(int major, int minor, int patch) implements Comparable<FirmwareVersion> {

    private static final Pattern FORMAT = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");

    public static FirmwareVersion parse(String text) {
        Matcher m = text == null ? null : FORMAT.matcher(text);
        if (m == null || !m.matches()) {
            throw new InvalidInputException("Firmware version must look like 1.2.3");
        }
        return new FirmwareVersion(Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3)));
    }

    @Override
    public int compareTo(FirmwareVersion other) {
        int byMajor = Integer.compare(major, other.major);
        if (byMajor != 0) {
            return byMajor;
        }
        int byMinor = Integer.compare(minor, other.minor);
        return byMinor != 0 ? byMinor : Integer.compare(patch, other.patch);
    }

    @Override
    public String toString() {
        return major + "." + minor + "." + patch;
    }
}
