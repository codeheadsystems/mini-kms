package com.codeheadsystems.minikms.master;

/**
 * Tunable Argon2id cost parameters, persisted alongside the salt so the same
 * passphrase reproduces the same master key across restarts.
 *
 * <p>The defaults are a deliberately conservative, well-documented middle ground
 * suitable for a single-machine service:
 *
 * <ul>
 *   <li><b>memory = 64 MiB</b> ({@value #DEFAULT_MEMORY_KIB} KiB) — the dominant
 *       cost; raises the price of brute force on custom hardware.</li>
 *   <li><b>iterations = {@value #DEFAULT_ITERATIONS}</b> — passes over memory.</li>
 *   <li><b>parallelism = {@value #DEFAULT_PARALLELISM}</b> — independent lanes.</li>
 * </ul>
 *
 * <p>These sit comfortably above OWASP's Argon2id floor (19 MiB, t=2, p=1) while
 * deriving the key in well under a second on commodity hardware. Because the
 * parameters are stored in the keystore metadata file, they can be raised later
 * without breaking existing installs (each install reads back its own values).
 *
 * @param memoryKiB    memory cost in kibibytes.
 * @param iterations   number of passes (time cost).
 * @param parallelism  number of parallel lanes.
 */
public record Argon2Settings(int memoryKiB, int iterations, int parallelism) {

  /** Default memory cost: 64 MiB. */
  public static final int DEFAULT_MEMORY_KIB = 64 * 1024;

  /** Default time cost: 3 passes. */
  public static final int DEFAULT_ITERATIONS = 3;

  /** Default parallelism: 1 lane. */
  public static final int DEFAULT_PARALLELISM = 1;

  /** Validate ranges. */
  public Argon2Settings {
    if (memoryKiB < 8) {
      throw new IllegalArgumentException("Argon2 memory must be at least 8 KiB");
    }
    if (iterations < 1) {
      throw new IllegalArgumentException("Argon2 iterations must be at least 1");
    }
    if (parallelism < 1) {
      throw new IllegalArgumentException("Argon2 parallelism must be at least 1");
    }
  }

  /** @return the documented default parameters. */
  public static Argon2Settings defaults() {
    return new Argon2Settings(DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
  }
}
