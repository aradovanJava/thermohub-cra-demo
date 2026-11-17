package demo.thermohub.cra.config;

import java.time.Clock;
import java.time.Duration;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import demo.thermohub.cra.security.AttemptLimiter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Deny by default (A01) and secure by default (A02, Annex I Part I (2)(b)).
     * Only health/info and the vulnerability-reporting contact are public.
     */
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http
            // RISK-001: stateless API for devices and the CLI, no cookies, no browser sessions.
            // Documented in config/spotbugs/security-exclude.xml and docs/cra/risk-assessment.md.
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Spring Security's default headers stay ON; we only tighten CSP for a JSON-only API.
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'")))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll()
                .requestMatchers("/.well-known/security.txt", "/error").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasAnyRole("USER", "ADMIN")
                .anyRequest().denyAll())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /** A04: adaptive, salted hashing (bcrypt by default) with algorithm agility via {id} prefixes. */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Publishes authentication success/failure events – feeds throttling (A07) and audit (A09). */
    @Bean
    AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    /** Five failures per 15 minutes per account or per device serial (A06, A07). */
    @Bean
    AttemptLimiter attemptLimiter() {
        return new AttemptLimiter(5, Duration.ofMinutes(15), Clock.systemUTC());
    }
}
