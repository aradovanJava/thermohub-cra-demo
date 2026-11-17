package demo.thermohub.cra;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import demo.thermohub.conformance.CraConformanceSuite;

/**
 * The same CRA conformance suite against the retrofitted product. Expected result: GREEN.
 * Runs in every build – a red test here breaks the build.
 */
@SpringBootTest
@ActiveProfiles("demo")
class ThermoHubCraConformanceTest extends CraConformanceSuite {

    @Value("${thermohub.demo.bob.password}")
    private String bobPassword;

    @Override
    protected String bobPassword() {
        return bobPassword;
    }
}
