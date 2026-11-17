package demo.thermohub.legacy.device;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

@Repository
public class DeviceRepository {

    private static final String COLUMNS = "id, owner, name, serial, firmware, setpoint";

    private static final RowMapper<Device> DEVICE = (rs, row) -> new Device(
            rs.getLong("id"),
            rs.getString("owner"),
            rs.getString("name"),
            rs.getString("serial"),
            rs.getString("firmware"),
            rs.getBigDecimal("setpoint"));

    private final JdbcTemplate jdbc;

    public DeviceRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Device> findByOwner(String owner) {
        return jdbc.query("SELECT " + COLUMNS + " FROM devices WHERE owner = ? ORDER BY id", DEVICE, owner);
    }

    /** A01: looks a device up by id only – whoever asks, gets it. */
    public Optional<Device> findById(long id) {
        return jdbc.query("SELECT " + COLUMNS + " FROM devices WHERE id = ?", DEVICE, id).stream().findFirst();
    }

    /** A05:2025 Injection – the search term is concatenated into the SQL statement. */
    public List<Device> search(String owner, String term) {
        String sql = "SELECT " + COLUMNS + " FROM devices "
                + "WHERE owner = '" + owner + "' AND name LIKE '%" + term + "%'";
        return jdbc.query(sql, DEVICE);
    }

    public void updateSetpoint(long id, BigDecimal celsius) {
        jdbc.update("UPDATE devices SET setpoint = ? WHERE id = ?", celsius, id);
    }

    public void rename(long id, String name) {
        jdbc.update("UPDATE devices SET name = ? WHERE id = ?", name, id);
    }

    public void storeWifiSecret(long id, String encryptedSecret) {
        jdbc.update("UPDATE devices SET wifi_secret = ? WHERE id = ?", encryptedSecret, id);
    }

    /** A06: a 4-digit code and no attempt limit – 10,000 guesses claim any thermostat. */
    public boolean pair(String serial, String code, String newOwner) {
        return jdbc.update("UPDATE devices SET owner = ?, pairing_code = NULL "
                + "WHERE serial = ? AND pairing_code = ? AND owner IS NULL", newOwner, serial, code) == 1;
    }
}
