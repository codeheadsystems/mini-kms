package com.codeheadsystems.minikms.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minikms.auth.AllowAllPolicy;
import com.codeheadsystems.minikms.auth.ApiTokenAuthenticator;
import com.codeheadsystems.minikms.keyring.LocalKeyring;
import com.codeheadsystems.minikms.kms.DataKey;
import com.codeheadsystems.minikms.kms.KmsRequestHandler;
import com.codeheadsystems.minikms.kms.KmsService;
import com.codeheadsystems.minikms.protocol.ErrorCode;
import com.codeheadsystems.minikms.server.KmsServer;
import com.codeheadsystems.minikms.server.ServerConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Boots the real server on an ephemeral loopback port and a temp Unix socket,
 * then drives both planes through the real {@link KmsClient}: data-plane crypto
 * over both transports, plus control-plane key management, rotation, re-encrypt,
 * and the data/admin token separation.
 */
class EndToEndIntegrationTest {

  private static final String API_TOKEN = "data-token";
  private static final String ADMIN_TOKEN = "admin-token";

  @TempDir
  Path tempDir;

  private LocalKeyring keyring;
  private KmsServer server;
  private int tcpPort;
  private Path unixSocket;

  @BeforeEach
  void startServer() throws Exception {
    unixSocket = tempDir.resolve("kms.sock");
    keyring = LocalKeyring.bootstrap(tempDir.resolve("keystore.json"),
        "passphrase".toCharArray(), new com.codeheadsystems.minikms.master.Argon2Settings(2048, 1, 1));
    final KmsRequestHandler handler = new KmsRequestHandler(
        new KmsService(keyring), keyring,
        new ApiTokenAuthenticator(API_TOKEN), new ApiTokenAuthenticator(ADMIN_TOKEN), new AllowAllPolicy());
    final ServerConfig config = ServerConfig.resolve(
        new String[]{"--tcp-port", "0", "--unix-socket", unixSocket.toString()}, Map.of());
    server = new KmsServer(config, handler);
    server.start();
    tcpPort = server.boundTcpPort();
  }

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.close();
    }
    if (keyring != null) {
      keyring.close();
    }
  }

  private KmsClient data(final boolean unix) {
    return unix ? KmsClient.connectUnix(unixSocket, API_TOKEN)
        : KmsClient.connectTcp("127.0.0.1", tcpPort, API_TOKEN);
  }

  private KmsClient admin() {
    return KmsClient.connectTcp("127.0.0.1", tcpPort, ADMIN_TOKEN);
  }

  // ---- data plane over both transports ----

  @Test
  void healthOverBothTransports() {
    try (KmsClient tcp = data(false); KmsClient unix = data(true)) {
      assertTrue(tcp.health());
      assertTrue(unix.health());
    }
  }

  @Test
  void generateDataKeyUnwrapsCorrectly() {
    try (KmsClient client = data(false)) {
      final DataKey dataKey = client.generateDataKey(null);
      assertEquals(32, dataKey.plaintext().length);
      assertArrayEquals(dataKey.plaintext(), client.decrypt(dataKey.wrapped(), null));
    }
  }

  @Test
  void endToEndFileEnvelopeOverUnix() {
    try (KmsClient client = data(true)) {
      final EnvelopeFileService service = new EnvelopeFileService(client);
      final byte[] content = "the quick brown fox".repeat(100).getBytes(StandardCharsets.UTF_8);
      final byte[] aad = "filename=secret.txt".getBytes(StandardCharsets.UTF_8);
      final byte[] container = service.encrypt(content, aad);
      assertFalse(new String(container, StandardCharsets.UTF_8).contains("quick brown"));
      assertArrayEquals(content, service.decrypt(container, aad));
    }
  }

  // ---- control plane + rotation ----

  @Test
  void rotationKeepsOldFileEnvelopesDecryptable() {
    final byte[] container;
    final byte[] content = "rotate me".getBytes(StandardCharsets.UTF_8);
    try (KmsClient client = data(false)) {
      container = new EnvelopeFileService(client).encrypt(content, null);
    }
    // Rotate the default group via the admin client.
    try (KmsClient adminClient = admin()) {
      assertEquals(2, adminClient.rotateKeyGroup("default").activeVersion());
    }
    // The pre-rotation file still decrypts (its wrapped DEK names v1).
    try (KmsClient client = data(false)) {
      assertArrayEquals(content, new EnvelopeFileService(client).decrypt(container, null));
    }
  }

  @Test
  void perGroupEncryptionAndReEncryptMigratesGroups() {
    try (KmsClient adminClient = admin()) {
      adminClient.createKeyGroup("billing");
    }
    try (KmsClient client = data(false)) {
      final byte[] underBilling = client.encrypt("billing", new byte[]{1, 2, 3}, null);
      assertArrayEquals(new byte[]{1, 2, 3}, client.decrypt(underBilling, null));
      // Migrate it to the default group with ReEncrypt; plaintext stays server-side.
      final byte[] underDefault = client.reEncrypt("default", underBilling, null);
      assertArrayEquals(new byte[]{1, 2, 3}, client.decrypt(underDefault, null));
    }
  }

  @Test
  void listKeyGroupsReflectsControlPlaneChanges() {
    try (KmsClient adminClient = admin()) {
      adminClient.createKeyGroup("g2");
      adminClient.rotateKeyGroup("g2");
      assertEquals(2, adminClient.listKeyGroups().size());
      assertEquals(2, adminClient.listKeyGroups().stream()
          .filter(g -> g.keyId().equals("g2")).findFirst().orElseThrow().activeVersion());
    }
  }

  // ---- token separation ----

  @Test
  void apiTokenCannotPerformControlOps() {
    try (KmsClient client = KmsClient.connectTcp("127.0.0.1", tcpPort, API_TOKEN)) {
      final KmsClientException ex = assertThrows(KmsClientException.class,
          () -> client.rotateKeyGroup("default"));
      assertEquals(ErrorCode.AUTH_FAILED, ex.errorCode());
    }
  }

  @Test
  void adminTokenCannotPerformDataOps() {
    try (KmsClient client = KmsClient.connectTcp("127.0.0.1", tcpPort, ADMIN_TOKEN)) {
      final KmsClientException ex = assertThrows(KmsClientException.class,
          () -> client.encrypt(new byte[]{1}, null));
      assertEquals(ErrorCode.AUTH_FAILED, ex.errorCode());
    }
  }

  @Test
  void wrongTokenRejectedOverBothTransports() {
    try (KmsClient client = KmsClient.connectTcp("127.0.0.1", tcpPort, "bogus")) {
      assertEquals(ErrorCode.AUTH_FAILED,
          assertThrows(KmsClientException.class, () -> client.generateDataKey(null)).errorCode());
    }
    try (KmsClient client = KmsClient.connectUnix(unixSocket, "bogus")) {
      assertEquals(ErrorCode.AUTH_FAILED,
          assertThrows(KmsClientException.class, () -> client.encrypt(new byte[]{1}, null)).errorCode());
    }
  }
}
