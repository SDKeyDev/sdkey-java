package dev.sdkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import dev.sdkey.crypto.Encoding;
import dev.sdkey.crypto.Seal;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class SealTest {
  private static final SecureRandom RANDOM = new SecureRandom();

  @Test
  void aesGcmRoundTripsPlaintext() {
    byte[] aesKey = new byte[32];
    RANDOM.nextBytes(aesKey);
    byte[] plaintext = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
    Seal.SealedEnvelope sealed = Seal.sealAesGcm(aesKey, plaintext);
    byte[] opened = Seal.openAesGcm(aesKey, sealed);
    assertEquals(
        new String(plaintext, StandardCharsets.UTF_8), new String(opened, StandardCharsets.UTF_8));
  }

  @Test
  void deriveSessionAesKeyIsDeterministic() {
    byte[] clientNonce = new byte[32];
    byte[] serverNonce = new byte[32];
    byte[] salt = new byte[16];
    RANDOM.nextBytes(clientNonce);
    RANDOM.nextBytes(serverNonce);
    RANDOM.nextBytes(salt);
    String saltB64 = Encoding.bytesToBase64(salt);
    String appId = "11111111-2222-3333-4444-555555555555";

    byte[] a = Seal.deriveSessionAesKey(clientNonce, serverNonce, saltB64, appId);
    byte[] b = Seal.deriveSessionAesKey(clientNonce, serverNonce, saltB64, appId);

    assertEquals(Encoding.bytesToBase64(a), Encoding.bytesToBase64(b));
    assertEquals(32, a.length);
  }

  @Test
  void deriveSessionAesKeyChangesWhenAppIdChanges() {
    byte[] clientNonce = new byte[32];
    Arrays.fill(clientNonce, (byte) 1);
    byte[] serverNonce = new byte[32];
    Arrays.fill(serverNonce, (byte) 2);
    byte[] salt = new byte[16];
    Arrays.fill(salt, (byte) 3);
    String saltB64 = Encoding.bytesToBase64(salt);

    byte[] a =
        Seal.deriveSessionAesKey(
            clientNonce, serverNonce, saltB64, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    byte[] b =
        Seal.deriveSessionAesKey(
            clientNonce, serverNonce, saltB64, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    assertNotEquals(Encoding.bytesToBase64(a), Encoding.bytesToBase64(b));
  }
}
