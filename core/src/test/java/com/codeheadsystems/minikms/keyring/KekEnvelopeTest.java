package com.codeheadsystems.minikms.keyring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class KekEnvelopeTest {

  @Test
  void serializeThenParseRoundTrips() {
    final KekEnvelope original = new KekEnvelope(new KekId("billing", 7), new byte[]{1, 2, 3, 4});
    final KekEnvelope parsed = KekEnvelope.parse(original.serialize());
    assertEquals("billing", parsed.kekId().keyGroupId());
    assertEquals(7, parsed.kekId().version());
    assertArrayEquals(new byte[]{1, 2, 3, 4}, parsed.innerEnvelope());
  }

  @Test
  void peekReadsKeyIdWithoutFullParseSemantics() {
    final byte[] blob = new KekEnvelope(new KekId("default", 1), new byte[]{9}).serialize();
    final KekId id = KekEnvelope.peekKekId(blob);
    assertEquals("default", id.keyGroupId());
    assertEquals(1, id.version());
  }

  @Test
  void rejectsUnknownVersion() {
    final byte[] blob = new KekEnvelope(new KekId("g", 1), new byte[]{1}).serialize();
    blob[0] = 0x09;
    assertThrows(IllegalArgumentException.class, () -> KekEnvelope.parse(blob));
  }

  @Test
  void rejectsTruncatedHeader() {
    assertThrows(IllegalArgumentException.class, () -> KekEnvelope.parse(new byte[]{0x02, 0x05}));
  }

  @Test
  void kekIdRejectsBlankGroupAndZeroVersion() {
    assertThrows(IllegalArgumentException.class, () -> new KekId("", 1));
    assertThrows(IllegalArgumentException.class, () -> new KekId("g", 0));
  }
}
