package com.github.feng111627.springauthaccesscontroljava.auth;

import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.login.LoginRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.login.SourceRateLimiter;
import com.github.feng111627.springauthaccesscontroljava.security.PasswordEncoder;
import com.github.feng111627.springauthaccesscontroljava.security.TokenError;
import com.github.feng111627.springauthaccesscontroljava.security.TokenException;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPair;
import com.github.feng111627.springauthaccesscontroljava.security.TokenPayload;
import com.github.feng111627.springauthaccesscontroljava.security.TokenRevocationService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenService;
import com.github.feng111627.springauthaccesscontroljava.security.TokenType;
import com.github.feng111627.springauthaccesscontroljava.user.User;
import com.github.feng111627.springauthaccesscontroljava.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orchestrates login, refresh and logout.
 *
 * <p>Failure outcomes are always distinguishable:
 * <ul>
 *   <li>{@link LoginError#RATE_LIMITED} / {@link LoginError#ACCOUNT_LOCKED}
 *       are decided by {@link LoginRateLimiter} (per-username) before any
 *       secret is checked;</li>
 *   <li>{@link LoginError#SOURCE_RATE_LIMITED} is decided by
 *       {@link SourceRateLimiter} (per client source, aggregating failures
 *       across all usernames) — evaluated strictly after the per-username
 *       gate, so when both dimensions trip the per-account result wins,
 *       consistently;</li>
 *   <li>{@link LoginError#BAD_CREDENTIALS} covers both unknown username and
 *       wrong password with the same response shape;</li>
 *   <li>{@link LoginError#ACCOUNT_DISABLED} is reported only after correct
 *       credentials are presented for a disabled account.</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final TokenRevocationService revocationService;
    private final LoginRateLimiter loginRateLimiter;
    private final SourceRateLimiter sourceRateLimiter;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       TokenService tokenService,
                       TokenRevocationService revocationService,
                       LoginRateLimiter loginRateLimiter,
                       SourceRateLimiter sourceRateLimiter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.revocationService = revocationService;
        this.loginRateLimiter = loginRateLimiter;
        this.sourceRateLimiter = sourceRateLimiter;
    }

    public TokenPair login(String username, String rawPassword, String source) {
        if (username == null || username.isBlank() || rawPassword == null) {
            throw new LoginException(LoginError.BAD_CREDENTIALS,
                    "Username and password are required");
        }
        String src = (source == null || source.isBlank()) ? "unknown" : source;

        // Serialize the whole decision per source (outer) and per username
        // (inner). The lock acquisition order is fixed — source first, then
        // username — so concurrent attempts for different (source, username)
        // pairs can never deadlock, while attempts sharing either dimension
        // are serialized and their counters stay exact.
        synchronized (sourceRateLimiter.lockFor(src)) {
            synchronized (loginRateLimiter.lockFor(username)) {
                // Gates first, in a fixed priority: the per-username gate
                // (lockout / per-username throttle) is evaluated before the
                // per-source gate. A blocked attempt never reaches the
                // password check (no oracle about the password) and is not
                // recorded as a failure in either dimension.
                loginRateLimiter.assertAttemptAllowed(username);
                sourceRateLimiter.assertAttemptAllowed(src);

                User user = userRepository.findByUsername(username).orElse(null);
                if (user == null) {
                    // Count failures against the presented username AND the
                    // source, so probing non-existent accounts is throttled
                    // on both dimensions just the same.
                    recordFailure(username, src);
                    throw new LoginException(LoginError.BAD_CREDENTIALS,
                            "Invalid username or password");
                }

                boolean passwordMatches;
                try {
                    passwordMatches = passwordEncoder.matches(
                            rawPassword, user.getPasswordHash());
                } catch (Exception e) {
                    recordFailure(username, src);
                    throw new LoginException(LoginError.BAD_CREDENTIALS,
                            "Invalid username or password");
                }

                if (!passwordMatches) {
                    recordFailure(username, src);
                    throw new LoginException(LoginError.BAD_CREDENTIALS,
                            "Invalid username or password");
                }

                if (!user.isEnabled()) {
                    // Correct credentials, disabled account: distinct outcome.
                    // Does not count as a credential failure and does not issue tokens.
                    throw new LoginException(LoginError.ACCOUNT_DISABLED,
                            "Account is disabled; contact an administrator");
                }

                // Success clears the per-username counters; the per-source
                // window intentionally keeps its failures (a success does not
                // erase a preceding brute-force burst from the same source).
                loginRateLimiter.recordSuccess(username);
                TokenPair pair = tokenService.issue(
                        user.getUsername(), user.getTokenEpoch());
                log.info("Login succeeded for user '{}' at epoch {}",
                        username, user.getTokenEpoch());
                return pair;
            }
        }
    }

    private void recordFailure(String username, String source) {
        loginRateLimiter.recordFailure(username);
        sourceRateLimiter.recordFailure(source);
    }

    /**
     * Rotates tokens using a valid, non-revoked refresh token.
     * The presented refresh token is revoked (rotation): reusing it, even
     * before natural expiry, yields {@link TokenError#REVOKED}.
     */
    public TokenPair refresh(String refreshToken) {
        TokenPayload payload = tokenService.verify(refreshToken, TokenType.REFRESH);
        if (revocationService.isRevoked(payload.jti())) {
            throw new TokenException(TokenError.REVOKED);
        }

        User user = userRepository.findByUsername(payload.subject()).orElse(null);
        if (user == null) {
            throw new TokenException(TokenError.REVOKED);
        }
        if (!user.isEnabled()) {
            throw new TokenException(TokenError.USER_DISABLED);
        }
        if (payload.epoch() != user.getTokenEpoch()) {
            // Permissions/state changed since this token was issued.
            throw new TokenException(TokenError.STALE_EPOCH);
        }

        // Rotate: revoke the presented token, issue a fresh pair.
        revocationService.revoke(payload.jti());
        return tokenService.issue(user.getUsername(), user.getTokenEpoch());
    }

    /** Logout revokes the presented refresh token; access tokens simply expire. */
    public void logout(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return;
        }
        try {
            TokenPayload payload = tokenService.verify(refreshToken, TokenType.REFRESH);
            revocationService.revoke(payload.jti());
            log.info("Refresh token revoked for user '{}'", payload.subject());
        } catch (TokenException e) {
            // An already-invalid token needs no further revocation; logout
            // remains idempotent and never leaks which reason applied.
            log.debug("Logout with unusable refresh token: {}", e.getError());
        }
    }
}
