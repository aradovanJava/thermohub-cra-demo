package demo.thermohub.legacy.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            // A02: "the security headers broke the old support dashboard"
            .headers(headers -> headers.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // A02: "ops needs the actuator and it is internal anyway"
                .requestMatchers("/actuator/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /** A04: unsalted MD5 – every hash in a leaked table is one rainbow-table lookup away. */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new LegacyMd5PasswordEncoder();
    }

    /**
     * A07: no lockout, no throttling, and the factory account admin/admin ships in data.sql.
     */
    @Bean
    UserDetailsService userDetailsService(JdbcTemplate jdbc) {
        return username -> {
            List<UserDetails> found = jdbc.query(
                    "SELECT username, password_hash, role FROM users WHERE username = ?",
                    (rs, row) -> User.withUsername(rs.getString("username"))
                            .password(rs.getString("password_hash"))
                            .roles(rs.getString("role"))
                            .build(),
                    username);
            if (found.isEmpty()) {
                throw new UsernameNotFoundException("Unknown user");
            }
            return found.get(0);
        };
    }
}
