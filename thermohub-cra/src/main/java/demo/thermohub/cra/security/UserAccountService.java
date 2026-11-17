package demo.thermohub.cra.security;

import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Loads accounts and marks them locked while the {@link AttemptLimiter} says so. Spring Security
 * checks the lock before the password, so a locked account rejects even the correct password.
 */
@Service
public class UserAccountService implements UserDetailsService {

    private final JdbcTemplate jdbc;
    private final AttemptLimiter limiter;

    public UserAccountService(JdbcTemplate jdbc, AttemptLimiter limiter) {
        this.jdbc = jdbc;
        this.limiter = limiter;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        boolean locked = limiter.isBlocked(LoginThrottling.key(username));
        List<UserDetails> found = jdbc.query(
                "SELECT username, password_hash, role FROM users WHERE username = ?",
                (rs, row) -> User.withUsername(rs.getString("username"))
                        .password(rs.getString("password_hash"))
                        .roles(rs.getString("role"))
                        .accountLocked(locked)
                        .build(),
                username);
        if (found.isEmpty()) {
            throw new UsernameNotFoundException("Unknown user");
        }
        return found.get(0);
    }
}
