package com.github.feng111627.springauthaccesscontroljava.auth;

import com.github.feng111627.springauthaccesscontroljava.login.LoginError;
import com.github.feng111627.springauthaccesscontroljava.login.LoginException;
import com.github.feng111627.springauthaccesscontroljava.login.LoginRateLimiter;
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
 *       are decided by {@link LoginRateLimiter} before any secret is checked;</li>
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

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       TokenService tokenService,
                       TokenRevocationService revocationService,
                       LoginRateLimiter loginRateLimiter) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.revocationService = revocationService;
        this.loginRateLimiter = loginRateLimiter;
    }

    public TokenPair login(String username, String rawPassword) {
        if (username == null || username.isBlank() || rawPassword == null) {
            throw new LoginException(LoginError.BAD_CREDENTIALS,
                    "Username and password are required");
        }

        // Serialize the whole decision per username so the rate-limit/lock
        // gate and the resulting counter update can never interleave. Other
        // usernames are unaffected and still run in parallel.
        synchronized (loginRateLimiter.lockFor(username)) {
            // Gate first: a locked or throttled username never reaches the
            // password check (no oracle about the password).
            loginRateLimiter.assertAttemptAllowed(username);

            User user = userRepository.findByUsername(username).orElse(null);
            if (user == null) {
                // Count failures against the presented username so an attacker
                // probing non-existent accounts is throttled just the same.
                loginRateLimiter.recordFailure(username);
                throw new LoginException(LoginError.BAD_CREDENTIALS,
                        "Invalid username or password");
            }

            boolean passwordMatches;
            try {
                passwordMatches = passwordEncoder.matches(
                        rawPassword, user.getPasswordHash());
            } catch (Exception e) {
                loginRateLimiter.recordFailure(username);
                throw new LoginException(LoginError.BAD_CREDENTIALS,
                        "Invalid username or password");
            }

            if (!passwordMatches) {
                loginRateLimiter.recordFailure(username);
                throw new LoginException(LoginError.BAD_CREDENTIALS,
                        "Invalid username or password");
            }

            if (!user.isEnabled()) {
                // Correct credentials, disabled account: distinct outcome.
                // Does not count as a credential failure and does not issue tokens.
                throw new LoginException(LoginError.ACCOUNT_DISABLED,
                        "Account is disabled; contact an administrator");
            }

            loginRateLimiter.recordSuccess(username);
            TokenPair pair = tokenService.issue(
                    user.getUsername(), user.getTokenEpoch());
            log.info("Login succeeded for user '{}' at epoch {}",
                    username, user.getTokenEpoch());
            return pair;
        }
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
