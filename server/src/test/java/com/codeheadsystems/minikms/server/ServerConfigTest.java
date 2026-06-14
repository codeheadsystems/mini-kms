package com.codeheadsystems.minikms.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ServerConfigTest {

  @Test
  void defaultsWhenNothingProvided() {
    final ServerConfig config = ServerConfig.resolve(new String[]{}, Map.of("HOME", "/home/test"));
    assertTrue(config.tcpEnabled());
    assertTrue(config.unixEnabled());
    assertEquals(ServerConfig.DEFAULT_TCP_PORT, config.tcpPort());
    assertEquals("/home/test/.mini-kms/keystore.json", config.keystorePath().toString());
    assertEquals("/home/test/.mini-kms/kms.sock", config.unixSocketPath().toString());
  }

  @Test
  void flagsOverrideEnvironment() {
    final ServerConfig config = ServerConfig.resolve(
        new String[]{"--tcp-port", "5000"},
        Map.of("MINIKMS_TCP_PORT", "9999", "HOME", "/home/test"));
    assertEquals(5000, config.tcpPort());
  }

  @Test
  void environmentUsedWhenNoFlag() {
    final ServerConfig config = ServerConfig.resolve(
        new String[]{}, Map.of("MINIKMS_TCP_PORT", "7777", "HOME", "/home/test"));
    assertEquals(7777, config.tcpPort());
  }

  @Test
  void xdgDataHomeWins() {
    final ServerConfig config = ServerConfig.resolve(
        new String[]{}, Map.of("XDG_DATA_HOME", "/data", "HOME", "/home/test"));
    assertEquals("/data/mini-kms/keystore.json", config.keystorePath().toString());
  }

  @Test
  void canDisableTcp() {
    final ServerConfig config = ServerConfig.resolve(new String[]{"--no-tcp"}, Map.of("HOME", "/h"));
    assertFalse(config.tcpEnabled());
    assertTrue(config.unixEnabled());
  }

  @Test
  void disablingBothTransportsIsRejected() {
    assertThrows(IllegalArgumentException.class, () ->
        ServerConfig.resolve(new String[]{"--no-tcp", "--no-unix"}, Map.of("HOME", "/h")));
  }

  @Test
  void unknownFlagIsRejected() {
    assertThrows(IllegalArgumentException.class, () ->
        ServerConfig.resolve(new String[]{"--bogus"}, Map.of("HOME", "/h")));
  }

  @Test
  void tokenFilePathParsed() {
    final ServerConfig config = ServerConfig.resolve(
        new String[]{"--token-file", "/etc/minikms.token"}, Map.of("HOME", "/h"));
    assertEquals("/etc/minikms.token", config.tokenFilePath().toString());
  }

  @Test
  void adminTokenFilePathParsed() {
    final ServerConfig config = ServerConfig.resolve(
        new String[]{"--admin-token-file", "/etc/minikms-admin.token"}, Map.of("HOME", "/h"));
    assertEquals("/etc/minikms-admin.token", config.adminTokenFilePath().toString());
  }
}
