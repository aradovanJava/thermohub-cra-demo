package demo.thermohub.conformance;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Traceability link between an executable test, the OWASP Top 10:2025 risk it attacks and the
 * Cyber Resilience Act (Regulation (EU) 2024/2847) requirement it provides evidence for.
 * <p>
 * The {@link CraReportExtension} turns these annotations into a conformance report that can be
 * attached to the technical documentation (Annex VII).
 */
@Documented
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface CraRequirement {

    /** OWASP Top 10:2025 category, for example {@code "A01:2025 Broken Access Control"}. */
    String owasp();

    /** CRA references, for example {@code "Annex I Part I (2)(d)"}. */
    String[] cra();

    /** The essential requirement in plain words. */
    String requirement();
}
