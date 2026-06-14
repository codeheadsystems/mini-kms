package com.codeheadsystems.minikms.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ProtocolCodecTest {

  private final ProtocolCodec codec = new ProtocolCodec();

  @Test
  void requestRoundTrips() {
    final KmsRequest request = KmsRequest.encrypt("tok", "billing", "cGxhaW4=", "YWFk");
    final KmsRequest parsed = codec.decodeRequest(codec.encodeRequest(request));
    assertEquals(RequestType.ENCRYPT, parsed.type());
    assertEquals("tok", parsed.token());
    assertEquals("billing", parsed.keyId());
    assertEquals("cGxhaW4=", parsed.plaintext());
    assertEquals("YWFk", parsed.aad());
  }

  @Test
  void controlPlaneRequestRoundTrips() {
    final KmsRequest request = KmsRequest.versionOp(RequestType.DESTROY_VERSION, "admin", "g", 4);
    final KmsRequest parsed = codec.decodeRequest(codec.encodeRequest(request));
    assertEquals(RequestType.DESTROY_VERSION, parsed.type());
    assertEquals(RequestPlane.CONTROL, parsed.type().plane());
    assertEquals("g", parsed.keyId());
    assertEquals(4L, parsed.version());
  }

  @Test
  void keyGroupListingResponseRoundTrips() {
    final KeyGroupView view = new KeyGroupView("default", 2,
        java.util.List.of(new KekVersionView(1, "ENABLED", 100), new KekVersionView(2, "ACTIVE", 200)));
    final KmsResponse parsed = codec.decodeResponse(codec.encodeResponse(KmsResponse.groups(
        java.util.List.of(view))));
    assertTrue(parsed.isOk());
    assertEquals(1, parsed.keyGroups().size());
    assertEquals(2, parsed.keyGroups().get(0).activeVersion());
    assertEquals("ACTIVE", parsed.keyGroups().get(0).versions().get(1).status());
  }

  @Test
  void responseRoundTrips() {
    final KmsResponse response = KmsResponse.dataKey("cGxhaW4=", "d3JhcA==");
    final KmsResponse parsed = codec.decodeResponse(codec.encodeResponse(response));
    assertTrue(parsed.isOk());
    assertEquals("cGxhaW4=", parsed.plaintextDataKey());
    assertEquals("d3JhcA==", parsed.wrappedDataKey());
  }

  @Test
  void encodedRequestIsSingleLine() {
    final String json = codec.encodeRequest(KmsRequest.health("tok"));
    assertFalse(json.contains("\n"), "wire frames must be single-line JSON");
  }

  @Test
  void nullFieldsAreOmitted() {
    final String json = codec.encodeRequest(KmsRequest.health("tok"));
    assertFalse(json.contains("plaintext"));
    assertFalse(json.contains("ciphertext"));
  }

  @Test
  void pingIsAcceptedAsHealthAlias() {
    final KmsRequest parsed = codec.decodeRequest("{\"type\":\"Ping\",\"token\":\"t\"}");
    assertEquals(RequestType.HEALTH, parsed.type());
  }

  @Test
  void errorResponseCarriesCodeAndMessage() {
    final KmsResponse parsed = codec.decodeResponse(
        codec.encodeResponse(KmsResponse.error(ErrorCode.AUTH_FAILED, "nope")));
    assertFalse(parsed.isOk());
    assertEquals(ErrorCode.AUTH_FAILED, parsed.errorCode());
    assertEquals("nope", parsed.message());
    assertNull(parsed.plaintext());
  }

  @Test
  void malformedJsonThrowsProtocolException() {
    assertThrows(ProtocolException.class, () -> codec.decodeRequest("{not json"));
  }

  @Test
  void unknownTypeThrowsProtocolException() {
    assertThrows(ProtocolException.class, () ->
        codec.decodeRequest("{\"type\":\"Bogus\",\"token\":\"t\"}"));
  }
}
