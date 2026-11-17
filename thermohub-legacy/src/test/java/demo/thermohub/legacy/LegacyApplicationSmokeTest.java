package demo.thermohub.legacy;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

/** The legacy product builds and starts – functionally it "works", which is the whole problem. */
@SpringBootTest
class LegacyApplicationSmokeTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void startsWithDemoData() {
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM devices", Integer.class)).isEqualTo(3);
    }
}
