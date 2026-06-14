package com.codeheadsystems.minikms.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ApiTokenAuthenticatorTest {

  private final ApiTokenAuthenticator auth = new ApiTokenAuthenticator("s3cr3t-token");

  @Test
  void acceptsExactToken() {
    assertTrue(auth.isValid("s3cr3t-token"));
  }

  @Test
  void rejectsWrongToken() {
    assertFalse(auth.isValid("nope"));
  }

  @Test
  void rejectsNull() {
    assertFalse(auth.isValid(null));
  }

  @Test
  void rejectsPrefixOfToken() {
    assertFalse(auth.isValid("s3cr3t"));
  }

  @Test
  void emptyExpectedTokenIsRejectedAtConstruction() {
    assertThrows(IllegalArgumentException.class, () -> new ApiTokenAuthenticator(""));
  }
}
