package demo.thermohub.cra.security;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sliding-window failure counter used for login throttling (A07) and pairing (A06).
 * <p>
 * After {@code maxFailures} failures inside {@code window} the key is blocked until the oldest
 * failure leaves the window. Bounded in size, so an attacker cannot exhaust memory with random keys
 * (Annex I Part I (2)(h) – availability).
 */
public final class AttemptLimiter {

    private static final int MAX_TRACKED_KEYS = 100_000;

    private final int maxFailures;
    private final Duration window;
    private final Clock clock;
    private final Map<String, Deque<Instant>> failures = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Deque<Instant>> eldest) {
            return size() > MAX_TRACKED_KEYS;
        }
    };

    public AttemptLimiter(int maxFailures, Duration window, Clock clock) {
        if (maxFailures < 1 || window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("maxFailures must be >= 1 and window positive");
        }
        this.maxFailures = maxFailures;
        this.window = window;
        this.clock = clock;
    }

    public synchronized boolean isBlocked(String key) {
        Deque<Instant> recent = failures.get(key);
        if (recent == null) {
            return false;
        }
        prune(recent);
        if (recent.isEmpty()) {
            failures.remove(key);
            return false;
        }
        return recent.size() >= maxFailures;
    }

    public synchronized void recordFailure(String key) {
        Deque<Instant> recent = failures.computeIfAbsent(key, k -> new ArrayDeque<>());
        recent.addLast(clock.instant());
        prune(recent);
    }

    public synchronized void reset(String key) {
        failures.remove(key);
    }

    private void prune(Deque<Instant> recent) {
        Instant cutoff = clock.instant().minus(window);
        while (!recent.isEmpty() && !recent.peekFirst().isAfter(cutoff)) {
            recent.pollFirst();
        }
    }
}
