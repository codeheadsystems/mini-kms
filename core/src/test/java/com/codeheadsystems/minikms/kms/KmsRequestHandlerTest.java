package com.codeheadsystems.minikms.kms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.auth.AllowAllPolicy;
import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.auth.KeyAuthorizationPolicy;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.master.Argon2Settings;
import com.codeheadsystems.minikms.protocol.ErrorCode;
import com.codeheadsystems.minikms.protocol.KmsRequest;
import com.codeheadsystems.minikms.protocol.KmsResponse;
import com.codeheadsystems.minikms.protocol.RequestType;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KmsRequestHandlerTest {

  private static final String API_TOKEN = "data-token";
  private static final String ADMIN_TOKEN = "admin-token";
  private static final Argon2Settings FAST = new Argon2Settings(2048, 1, 1);

  @TempDir
  Path tempDir;

  private LocalKeyring keyring;
  private KmsRequestHandler handler;

  @BeforeEach
  void setUp() {
    keyring = LocalKeyring.bootstrap(tempDir.resolve("ks.json"), "pw".toCharArray(), FAST);
    handler = newHandler(new AllowAllPolicy());
  }

  private KmsRequestHandler newHandler(final KeyAuthorizationPolicy policy) {
    return new KmsRequestHandler(new KmsService(keyring), keyring,
        new ApiTokenAuthenticator(API_TOKEN), new ApiTokenAuthenticator(ADMIN_TOKEN), policy);
  }

  @AfterEach
  void tearDown() {
    keyring.close();
  }

  // ---- data plane auth ----

  @Test
  void healthSucceedsWithApiToken() {
    assertTrue(handler.handle(KmsRequest.health(API_TOKEN)).isOk());
  }

  @Test
  void dataPlaneRejectsBadApiToken() {
    assertEquals(ErrorCode.AUTH_FAILED, handler.handle(KmsRequest.health("nope")).errorCode());
  }

  @Test
  void generateDataKeyRoundTripsThroughHandler() {
    final KmsResponse gen = handler.handle(KmsRequest.generateDataKey(API_TOKEN, null, null));
    assertTrue(gen.isOk());
    assertNotNull(gen.wrappedDataKey());

    final KmsResponse dec = handler.handle(KmsRequest.decrypt(API_TOKEN, gen.wrappedDataKey(), null));
    assertEquals(gen.plaintextDataKey(), dec.plaintext());
  }

  @Test
  void decryptOfGarbageIsDecryptionFailed() {
    final String garbage = Base64.getEncoder().encodeToString(new byte[]{2, 1, 1, 99, 0, 0});
    assertEquals(ErrorCode.DECRYPTION_FAILED,
        handler.handle(KmsRequest.decrypt(API_TOKEN, garbage, null)).errorCode());
  }

  // ---- control plane auth ----

  @Test
  void controlPlaneRequiresAdminTokenNotApiToken() {
    // The data token must NOT work for a control-plane op.
    assertEquals(ErrorCode.AUTH_FAILED,
        handler.handle(KmsRequest.listKeyGroups(API_TOKEN)).errorCode());
    // The admin token works.
    assertTrue(handler.handle(KmsRequest.listKeyGroups(ADMIN_TOKEN)).isOk());
  }

  @Test
  void adminTokenDoesNotGrantDataPlane() {
    // Symmetry: the admin token must not authorize data-plane ops.
    assertEquals(ErrorCode.AUTH_FAILED,
        handler.handle(KmsRequest.health(ADMIN_TOKEN)).errorCode());
  }

  @Test
  void createAndRotateReturnGroupViews() {
    final KmsResponse created = handler.handle(KmsRequest.createKeyGroup(ADMIN_TOKEN, "billing"));
    assertTrue(created.isOk());
    assertEquals("billing", created.keyGroup().keyId());
    assertEquals(1, created.keyGroup().activeVersion());

    final KmsResponse rotated = handler.handle(KmsRequest.rotateKeyGroup(ADMIN_TOKEN, "billing"));
    assertEquals(2, rotated.keyGroup().activeVersion());
  }

  @Test
  void listReflectsCreatedGroups() {
    handler.handle(KmsRequest.createKeyGroup(ADMIN_TOKEN, "g2"));
    final KmsResponse list = handler.handle(KmsRequest.listKeyGroups(ADMIN_TOKEN));
    assertTrue(list.isOk());
    assertEquals(2, list.keyGroups().size());
  }

  @Test
  void destroyingActiveVersionIsInvalidRequest() {
    final KmsResponse response =
        handler.handle(KmsRequest.versionOp(RequestType.DESTROY_VERSION, ADMIN_TOKEN, "default", 1));
    assertEquals(ErrorCode.INVALID_REQUEST, response.errorCode());
  }

  // ---- authorization policy ----

  @Test
  void authorizationPolicyCanDenyAGroup() {
    // Deny everything except the "default" group.
    handler = newHandler((principal, group, op) -> group.equals("default"));
    assertEquals(ErrorCode.UNAUTHORIZED,
        handler.handle(KmsRequest.encrypt(API_TOKEN, "secret-group",
            Base64.getEncoder().encodeToString(new byte[]{1}), null)).errorCode());
    assertTrue(handler.handle(KmsRequest.encrypt(API_TOKEN, "default",
        Base64.getEncoder().encodeToString(new byte[]{1}), null)).isOk());
  }
}
