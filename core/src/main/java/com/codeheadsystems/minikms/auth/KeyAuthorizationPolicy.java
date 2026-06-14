package com.codeheadsystems.minikms.auth;

/**
 * Decides whether a {@link Principal} may perform a {@link KeyOperation} against a
 * particular key group. This is the explicit seam for "KEK groups dependent on
 * the client".
 *
 * <p>The shipped default is {@link AllowAllPolicy}: with a single shared token
 * there is only one data-plane principal, so any authenticated client may use any
 * group (groups still provide isolation and independent rotation). Introducing
 * per-client tokens later means mapping each token to a distinct {@link Principal}
 * and supplying a policy here that restricts groups per principal — with no change
 * to the request-handling code that calls this.
 */
public interface KeyAuthorizationPolicy {

  /**
   * @param principal  the authenticated caller.
   * @param keyGroupId the key group being accessed.
   * @param operation  the operation being attempted.
   * @return whether the operation is permitted.
   */
  boolean isAllowed(Principal principal, String keyGroupId, KeyOperation operation);
}
