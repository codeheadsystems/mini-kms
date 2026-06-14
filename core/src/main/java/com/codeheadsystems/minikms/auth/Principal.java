package com.codeheadsystems.minikms.auth;

/**
 * The authenticated identity behind a request.
 *
 * <p>Today authentication is a single shared token, so there is effectively one
 * data-plane principal and one admin principal. This type exists as the seam for
 * a future per-client model (e.g. one token per client mapped to a distinct
 * principal), at which point {@link KeyAuthorizationPolicy} can grant different
 * principals access to different key groups.
 *
 * @param id    a stable identifier for the caller.
 * @param admin whether this principal authenticated on the control plane.
 */
public record Principal(String id, boolean admin) {

  /** The single shared data-plane identity used until per-client tokens exist. */
  public static final Principal SHARED_DATA_CLIENT = new Principal("shared-data-client", false);

  /** The single shared control-plane (admin) identity. */
  public static final Principal SHARED_ADMIN = new Principal("shared-admin", true);
}
