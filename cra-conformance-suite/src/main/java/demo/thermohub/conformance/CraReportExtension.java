package demo.thermohub.conformance;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.TestWatcher;

/**
 * Collects the outcome of every {@link CraRequirement}-annotated test and prints a compliance
 * summary after the test class finishes. A Markdown copy is written to
 * {@code target/cra-conformance-report-<TestClass>.md} – build evidence for the technical documentation.
 */
public class CraReportExtension implements TestWatcher, AfterAllCallback {

    private enum Status { PASS, FAIL, ABORTED, DISABLED }

    private record Result(String owasp, String cra, String requirement, Status status, String detail) { }

    private static final Map<String, List<Result>> RESULTS = new ConcurrentHashMap<>();

    @Override
    public void testSuccessful(ExtensionContext context) {
        record(context, Status.PASS, "");
    }

    @Override
    public void testFailed(ExtensionContext context, Throwable cause) {
        record(context, Status.FAIL, summarise(cause.getMessage()));
    }

    @Override
    public void testAborted(ExtensionContext context, Throwable cause) {
        record(context, Status.ABORTED, cause == null ? "" : summarise(cause.getMessage()));
    }

    @Override
    public void testDisabled(ExtensionContext context, Optional<String> reason) {
        record(context, Status.DISABLED, reason.orElse(""));
    }

    @Override
    public void afterAll(ExtensionContext context) {
        String suite = context.getRequiredTestClass().getSimpleName();
        List<Result> results = RESULTS.getOrDefault(suite, List.of()).stream()
                .sorted(Comparator.comparing(Result::owasp))
                .toList();
        if (results.isEmpty()) {
            return;
        }
        long passed = results.stream().filter(r -> r.status() == Status.PASS).count();

        StringBuilder console = new StringBuilder();
        console.append(System.lineSeparator())
               .append("==== CRA conformance – ").append(suite).append(" ====").append(System.lineSeparator());
        for (Result r : results) {
            console.append(r.status() == Status.PASS ? "  [PASS] " : "  [FAIL] ")
                   .append(pad(r.owasp(), 42)).append(" -> ").append(r.cra())
                   .append(System.lineSeparator());
        }
        console.append(String.format("  %d of %d essential-requirement checks met%n", passed, results.size()));
        System.out.println(console);

        writeMarkdown(suite, results, passed);
    }

    private static void record(ExtensionContext context, Status status, String detail) {
        context.getTestMethod()
                .map(method -> method.getAnnotation(CraRequirement.class))
                .ifPresent(req -> RESULTS
                        .computeIfAbsent(context.getRequiredTestClass().getSimpleName(), k -> new CopyOnWriteArrayList<>())
                        .add(new Result(req.owasp(), String.join("; ", req.cra()), req.requirement(), status, detail)));
    }

    private static void writeMarkdown(String suite, List<Result> results, long passed) {
        StringBuilder md = new StringBuilder();
        md.append("# CRA conformance report – ").append(suite).append("\n\n");
        md.append("Generated ").append(OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME))
          .append(" · ").append(passed).append(" of ").append(results.size()).append(" checks met\n\n");
        md.append("| Result | OWASP Top 10:2025 | CRA reference | Essential requirement | Evidence / failure |\n");
        md.append("|---|---|---|---|---|\n");
        for (Result r : results) {
            md.append("| ").append(r.status() == Status.PASS ? "PASS" : "**" + r.status() + "**")
              .append(" | ").append(r.owasp())
              .append(" | ").append(r.cra())
              .append(" | ").append(r.requirement())
              .append(" | ").append(r.detail().replace("|", "\\|"))
              .append(" |\n");
        }
        try {
            Path report = Path.of("target", "cra-conformance-report-" + suite + ".md");
            Files.createDirectories(report.getParent());
            Files.writeString(report, md.toString(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Could not write CRA conformance report", e);
        }
    }

    private static String summarise(String message) {
        if (message == null) {
            return "";
        }
        String flat = message.replaceAll("\\s+", " ").trim();
        return flat.length() > 180 ? flat.substring(0, 177) + "..." : flat;
    }

    private static String pad(String value, int width) {
        return value.length() >= width ? value : value + " ".repeat(width - value.length());
    }
}
