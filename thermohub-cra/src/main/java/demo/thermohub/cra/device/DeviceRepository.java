package demo.thermohub.cra.device;

import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/**
 * Every query is parameterised (A05) and every customer-facing read or write is scoped to the owner
 * in the WHERE clause (A01) – authorisation is enforced where the data is, not only in the controller.
 */
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

    public Optional<Device> findOwned(long id, String owner) {
        return jdbc.query("SELECT " + COLUMNS + " FROM devices WHERE id = ? AND owner = ?", DEVICE, id, owner)
                .stream().findFirst();
    }

    public Optional<Device> findBySerial(String serial) {
        return jdbc.query("SELECT " + COLUMNS + " FROM devices WHERE serial = ?", DEVICE, serial).stream().findFirst();
    }

    public List<Device> search(String owner, SearchTerm term) {
        return jdbc.query("SELECT " + COLUMNS + " FROM devices "
                        + "WHERE owner = ? AND LOWER(name) LIKE LOWER(?) ESCAPE '\\' ORDER BY id",
                DEVICE, owner, term.containsPattern());
    }

    public void updateSetpoint(long id, String owner, Setpoint setpoint) {
        jdbc.update("UPDATE devices SET setpoint = ? WHERE id = ? AND owner = ?", setpoint.celsius(), id, owner);
    }

    public void rename(long id, String owner, String name) {
        jdbc.update("UPDATE devices SET name = ? WHERE id = ? AND owner = ?", name, id, owner);
    }

    public void storeWifiSecret(long id, String owner, String envelope) {
        jdbc.update("UPDATE devices SET wifi_secret = ? WHERE id = ? AND owner = ?", envelope, id, owner);
    }

    public Optional<String> pairingCodeHashOfUnpaired(String serial) {
        return jdbc.queryForList("SELECT pairing_code FROM devices "
                        + "WHERE serial = ? AND owner IS NULL AND pairing_code IS NOT NULL", String.class, serial)
                .stream().findFirst();
    }

    public boolean assignOwner(String serial, String owner) {
        return jdbc.update("UPDATE devices SET owner = ?, pairing_code = NULL WHERE serial = ? AND owner IS NULL",
                owner, serial) == 1;
    }
}
