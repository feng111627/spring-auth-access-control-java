package com.github.feng111627.springauthaccesscontroljava.user;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * An in-memory user account.
 *
 * <p><b>Token lifecycle semantics:</b> every token embeds the account's
 * {@code tokenEpoch} at issue time. The epoch is incremented whenever
 * enabled-state, roles or permissions change. Requests whose token epoch
 * differs from the live epoch are rejected ({@code STALE_EPOCH}) before any
 * authorisation decision. Therefore an already-issued token's effective
 * permissions are always read live, and changes take effect immediately and
 * consistently — until the user re-logs in with the new epoch.
 */
public class User {

    private final String username;
    private final String passwordHash;
    private final Set<Role> roles = new HashSet<>();
    private final Set<String> permissions = new HashSet<>();
    private volatile boolean enabled;
    private volatile long tokenEpoch = 1;

    public User(String username, String passwordHash,
                Set<Role> roles, Set<String> permissions, boolean enabled) {
        this.username = Objects.requireNonNull(username, "username");
        this.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        if (roles != null) {
            this.roles.addAll(roles);
        }
        if (permissions != null) {
            this.permissions.addAll(permissions);
        }
        this.enabled = enabled;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public synchronized Set<Role> getRoles() {
        return Collections.unmodifiableSet(new HashSet<>(roles));
    }

    public synchronized Set<String> getPermissions() {
        return Collections.unmodifiableSet(new HashSet<>(permissions));
    }

    public boolean isEnabled() {
        return enabled;
    }

    public long getTokenEpoch() {
        return tokenEpoch;
    }

    /** Disable/enable the account and invalidate all previously issued tokens. */
    public void setEnabled(boolean enabled) {
        if (this.enabled != enabled) {
            this.enabled = enabled;
            tokenEpoch++;
        }
    }

    /** Replace roles and invalidate all previously issued tokens. */
    public void setRoles(Set<Role> newRoles) {
        synchronized (this) {
            Set<Role> copy = newRoles == null ? Set.of() : new HashSet<>(newRoles);
            if (!this.roles.equals(copy)) {
                this.roles.clear();
                this.roles.addAll(copy);
                tokenEpoch++;
            }
        }
    }

    /** Replace permissions and invalidate all previously issued tokens. */
    public void setPermissions(Set<String> newPermissions) {
        synchronized (this) {
            Set<String> copy = newPermissions == null
                    ? Set.of() : new HashSet<>(newPermissions);
            if (!this.permissions.equals(copy)) {
                this.permissions.clear();
                this.permissions.addAll(copy);
                tokenEpoch++;
            }
        }
    }
}
