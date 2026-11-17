package demo.thermohub.legacy;

import org.springframework.boot.test.context.SpringBootTest;

import demo.thermohub.conformance.CraConformanceSuite;

/**
 * The CRA conformance suite against the product as shipped in 2019. Expected result: RED.
 * <p>
 * Excluded from the default Maven build; run it from the IDE or with {@code -Pcra-gate}.
 */
@SpringBootTest
class LegacyCraConformanceTest extends CraConformanceSuite {

    @Override
    protected String bobPassword() {
        return "123456";
    }
}
