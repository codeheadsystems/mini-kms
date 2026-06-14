package com.codeheadsystems.minikms.auth;

/**
 * The default {@link KeyAuthorizationPolicy}: every authenticated principal may
 * use every key group. Appropriate while authentication is a single shared token.
 * Swap in a restrictive policy once per-client identities exist.
 */
public final class AllowAllPolicy implements KeyAuthorizationPolicy {

  @Override
  public boolean isAllowed(final Principal principal, final String keyGroupId, final KeyOperation operation) {
    return true;
  }
}
