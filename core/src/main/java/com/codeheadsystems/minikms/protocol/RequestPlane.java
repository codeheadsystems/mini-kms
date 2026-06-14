package com.codeheadsystems.minikms.protocol;

/**
 * Which plane a request belongs to, used to pick the authenticator.
 *
 * <ul>
 *   <li>{@link #DATA} — encrypt/decrypt/generate/re-encrypt; guarded by the API token.</li>
 *   <li>{@link #CONTROL} — create/rotate/list/disable/destroy keys; guarded by the admin token.</li>
 * </ul>
 */
public enum RequestPlane {
  /** Data-plane traffic (per-request crypto). */
  DATA,
  /** Control-plane traffic (key management). */
  CONTROL
}
