package dev.sdkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.sdkey.crypto.CanonicalJson;
import dev.sdkey.crypto.Constants;
import dev.sdkey.crypto.Encoding;
import dev.sdkey.crypto.Seal;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

class ClientTest {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final SecureRandom RANDOM = new SecureRandom();

  private static final class KeyPair {
    final Ed25519PrivateKeyParameters privateKey;
    final String publicKeyB64;

    KeyPair(Ed25519PrivateKeyParameters privateKey, String publicKeyB64) {
      this.privateKey = privateKey;
      this.publicKeyB64 = publicKeyB64;
    }
  }

  private static KeyPair generateEd25519Pair() {
    Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
    generator.init(new Ed25519KeyGenerationParameters(RANDOM));
    AsymmetricCipherKeyPair pair = generator.generateKeyPair();
    Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) pair.getPrivate();
    Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) pair.getPublic();
    return new KeyPair(privateKey, Encoding.bytesToBase64(publicKey.getEncoded()));
  }

  private static String signPayload(Ed25519PrivateKeyParameters privateKey, Object payload) {
    byte[] message = CanonicalJson.canonicalJsonBytes(payload);
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, privateKey);
    signer.update(message, 0, message.length);
    return Encoding.bytesToBase64(signer.generateSignature());
  }

  private static JsonNode toJsonNode(Object value) {
    return MAPPER.valueToTree(value);
  }

  @Test
  void initsSessionAndValidatesSealedLicenseResponse() throws Exception {
    KeyPair keys = generateEd25519Pair();
    String appId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    String appVersion = "1.0.0";
    String sessionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    byte[] serverNonce = new byte[32];
    byte[] hkdfSalt = new byte[16];
    RANDOM.nextBytes(serverNonce);
    RANDOM.nextBytes(hkdfSalt);
    long timestamp = Instant.now().getEpochSecond();

    AtomicReference<byte[]> capturedClientNonce = new AtomicReference<>();
    AtomicReference<String> capturedInitBody = new AtomicReference<>();
    AtomicReference<String> capturedValidateInner = new AtomicReference<>();
    AtomicInteger callCount = new AtomicInteger();

    SdkeyHttpPost httpPost =
        (url, body) -> {
          callCount.incrementAndGet();
          JsonNode bodyEl = toJsonNode(body);

          if (url.endsWith("/api/v1/session/init")) {
            capturedInitBody.set(MAPPER.writeValueAsString(body));
            assertEquals(appVersion, bodyEl.get("clientVersion").asText());
            capturedClientNonce.set(
                Encoding.base64ToBytes(bodyEl.get("clientNonceB64").asText()));

            Map<String, Object> hello = new LinkedHashMap<>();
            hello.put("appId", appId);
            hello.put("hkdfSaltB64", Encoding.bytesToBase64(hkdfSalt));
            hello.put("serverNonceB64", Encoding.bytesToBase64(serverNonce));
            hello.put("sessionId", sessionId);
            hello.put("timestamp", timestamp);
            hello.put("v", Constants.PROTOCOL_VERSION);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("appId", appId);
            response.put("hkdfSaltB64", Encoding.bytesToBase64(hkdfSalt));
            response.put("serverNonceB64", Encoding.bytesToBase64(serverNonce));
            response.put("sessionId", sessionId);
            response.put("timestamp", timestamp);
            response.put("v", Constants.PROTOCOL_VERSION);
            response.put("signatureB64", signPayload(keys.privateKey, hello));
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
          }

          if (url.endsWith("/api/v1/licenses/validate")) {
            assertNotNull(capturedClientNonce.get());
            byte[] aesKey =
                Seal.deriveSessionAesKey(
                    capturedClientNonce.get(),
                    serverNonce,
                    Encoding.bytesToBase64(hkdfSalt),
                    appId);

            byte[] opened =
                Seal.openAesGcm(
                    aesKey,
                    new Seal.SealedEnvelope(
                        bodyEl.get("ivB64").asText(),
                        bodyEl.get("ciphertextB64").asText(),
                        bodyEl.get("tagB64").asText()));
            capturedValidateInner.set(new String(opened, StandardCharsets.UTF_8));

            Map<String, Object> plaintext = new LinkedHashMap<>();
            plaintext.put("success", true);
            plaintext.put("code", "OK");
            plaintext.put("message", "validated");
            plaintext.put("status", "active");
            plaintext.put("expiresAt", null);
            plaintext.put("subscriptionTier", 2);
            plaintext.put("sessionId", sessionId);
            plaintext.put("timestamp", Instant.now().getEpochSecond());
            plaintext.put("v", Constants.PROTOCOL_VERSION);

            Seal.SealedEnvelope sealed =
                Seal.sealAesGcm(
                    aesKey, MAPPER.writeValueAsString(plaintext).getBytes(StandardCharsets.UTF_8));

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("sessionId", sessionId);
            response.put("ivB64", sealed.getIvB64());
            response.put("ciphertextB64", sealed.getCiphertextB64());
            response.put("tagB64", sealed.getTagB64());
            response.put("signatureB64", signPayload(keys.privateKey, plaintext));
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
          }

          return new SdkeyHttpPost.HttpResponse(
              404, toJsonNode(Map.of("error", "not found")));
        };

    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId(appId)
                .appVersion(appVersion)
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    ValidateResult result = client.validate("SDKY-TEST-TEST-TEST-TEST", "hwid-1");
    assertTrue(result.isSuccess());
    assertEquals("OK", result.getCode());
    assertEquals("validated", result.getMessage());
    assertEquals(2, result.getSubscriptionTier());
    assertNotNull(client.getSession());
    assertEquals(sessionId, client.getSession().getSessionId());
    assertEquals(2, callCount.get());
    assertTrue(capturedInitBody.get().contains("clientVersion"));
    assertTrue(capturedValidateInner.get().contains("\"hwid\":\"hwid-1\""));
  }

  @Test
  void omitsHwidFromValidatePayloadWhenAbsent() throws Exception {
    KeyPair keys = generateEd25519Pair();
    String appId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    String sessionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    byte[] serverNonce = new byte[32];
    byte[] hkdfSalt = new byte[16];
    RANDOM.nextBytes(serverNonce);
    RANDOM.nextBytes(hkdfSalt);
    long timestamp = Instant.now().getEpochSecond();
    AtomicReference<byte[]> capturedClientNonce = new AtomicReference<>();
    AtomicReference<String> capturedValidateInner = new AtomicReference<>();

    SdkeyHttpPost httpPost =
        (url, body) -> {
          JsonNode bodyEl = toJsonNode(body);

          if (url.endsWith("/api/v1/session/init")) {
            capturedClientNonce.set(
                Encoding.base64ToBytes(bodyEl.get("clientNonceB64").asText()));

            Map<String, Object> hello = new LinkedHashMap<>();
            hello.put("appId", appId);
            hello.put("hkdfSaltB64", Encoding.bytesToBase64(hkdfSalt));
            hello.put("serverNonceB64", Encoding.bytesToBase64(serverNonce));
            hello.put("sessionId", sessionId);
            hello.put("timestamp", timestamp);
            hello.put("v", Constants.PROTOCOL_VERSION);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("hkdfSaltB64", hello.get("hkdfSaltB64"));
            response.put("serverNonceB64", hello.get("serverNonceB64"));
            response.put("sessionId", sessionId);
            response.put("timestamp", timestamp);
            response.put("signatureB64", signPayload(keys.privateKey, hello));
            response.put("v", Constants.PROTOCOL_VERSION);
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
          }

          assertNotNull(capturedClientNonce.get());
          byte[] aesKey =
              Seal.deriveSessionAesKey(
                  capturedClientNonce.get(),
                  serverNonce,
                  Encoding.bytesToBase64(hkdfSalt),
                  appId);

          byte[] opened =
              Seal.openAesGcm(
                  aesKey,
                  new Seal.SealedEnvelope(
                      bodyEl.get("ivB64").asText(),
                      bodyEl.get("ciphertextB64").asText(),
                      bodyEl.get("tagB64").asText()));
          capturedValidateInner.set(new String(opened, StandardCharsets.UTF_8));

          Map<String, Object> plaintext = new LinkedHashMap<>();
          plaintext.put("success", true);
          plaintext.put("code", "OK");
          plaintext.put("message", "validated");
          plaintext.put("status", "active");
          plaintext.put("expiresAt", null);
          plaintext.put("subscriptionTier", 0);
          plaintext.put("sessionId", sessionId);
          plaintext.put("timestamp", Instant.now().getEpochSecond());
          plaintext.put("v", Constants.PROTOCOL_VERSION);

          Seal.SealedEnvelope sealed =
              Seal.sealAesGcm(
                  aesKey, MAPPER.writeValueAsString(plaintext).getBytes(StandardCharsets.UTF_8));

          Map<String, Object> response = new LinkedHashMap<>();
          response.put("sessionId", sessionId);
          response.put("ivB64", sealed.getIvB64());
          response.put("ciphertextB64", sealed.getCiphertextB64());
          response.put("tagB64", sealed.getTagB64());
          response.put("signatureB64", signPayload(keys.privateKey, plaintext));
          return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
        };

    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId(appId)
                .appVersion("1.0.0")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    ValidateResult result = client.validate("SDKY-TEST");
    assertTrue(result.isSuccess());
    assertEquals(0, result.getSubscriptionTier());
    assertFalse(capturedValidateInner.get().contains("hwid"));
  }

  @Test
  void surfacesServerErrorAndCodeOnInitFailure() {
    SdkeyHttpPost httpPost =
        (url, body) -> {
          Map<String, Object> response = new LinkedHashMap<>();
          response.put("success", false);
          response.put("error", "Client version outdated");
          response.put("code", "APP_OUTDATED");
          return new SdkeyHttpPost.HttpResponse(403, toJsonNode(response));
        };

    KeyPair keys = generateEd25519Pair();
    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .appVersion("0.0.1")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    SdkeyError err = assertThrows(SdkeyError.class, client::init);
    assertEquals("INIT_FAILED", err.getCode());
    assertEquals("Client version outdated", err.getMessage());
    assertEquals("APP_OUTDATED", err.getServerCode());
  }

  @Test
  void throwsSdkeyErrorWhenHelloSignatureIsWrong() {
    KeyPair keys = generateEd25519Pair();
    KeyPair other = generateEd25519Pair();

    SdkeyHttpPost httpPost =
        (url, body) -> {
          Map<String, Object> hello = new LinkedHashMap<>();
          hello.put("appId", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
          hello.put("hkdfSaltB64", Encoding.bytesToBase64(new byte[16]));
          hello.put("serverNonceB64", Encoding.bytesToBase64(new byte[32]));
          hello.put("sessionId", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
          hello.put("timestamp", Instant.now().getEpochSecond());
          hello.put("v", Constants.PROTOCOL_VERSION);

          Map<String, Object> response = new LinkedHashMap<>();
          response.put("success", true);
          response.put("appId", hello.get("appId"));
          response.put("hkdfSaltB64", hello.get("hkdfSaltB64"));
          response.put("serverNonceB64", hello.get("serverNonceB64"));
          response.put("sessionId", hello.get("sessionId"));
          response.put("timestamp", hello.get("timestamp"));
          response.put("v", hello.get("v"));
          response.put("signatureB64", signPayload(other.privateKey, hello));
          return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
        };

    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .appVersion("1.0.0")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    SdkeyError err = assertThrows(SdkeyError.class, client::init);
    assertEquals("HELLO_SIGNATURE_INVALID", err.getCode());
  }

  @Test
  void clearsSessionWhenValidateResponseIsSessionExpired() {
    KeyPair keys = generateEd25519Pair();
    String appId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    String sessionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    byte[] serverNonce = new byte[32];
    byte[] hkdfSalt = new byte[16];
    RANDOM.nextBytes(serverNonce);
    RANDOM.nextBytes(hkdfSalt);
    long timestamp = Instant.now().getEpochSecond();

    SdkeyHttpPost httpPost =
        (url, body) -> {
          if (url.endsWith("/api/v1/session/init")) {
            Map<String, Object> hello = new LinkedHashMap<>();
            hello.put("appId", appId);
            hello.put("hkdfSaltB64", Encoding.bytesToBase64(hkdfSalt));
            hello.put("serverNonceB64", Encoding.bytesToBase64(serverNonce));
            hello.put("sessionId", sessionId);
            hello.put("timestamp", timestamp);
            hello.put("v", Constants.PROTOCOL_VERSION);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("success", true);
            response.put("hkdfSaltB64", hello.get("hkdfSaltB64"));
            response.put("serverNonceB64", hello.get("serverNonceB64"));
            response.put("sessionId", sessionId);
            response.put("timestamp", timestamp);
            response.put("signatureB64", signPayload(keys.privateKey, hello));
            response.put("v", Constants.PROTOCOL_VERSION);
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
          }

          Map<String, Object> response = new LinkedHashMap<>();
          response.put("code", "SESSION_EXPIRED");
          response.put("error", "session expired");
          return new SdkeyHttpPost.HttpResponse(200, toJsonNode(response));
        };

    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId(appId)
                .appVersion("1.0.0")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    client.init();
    assertNotNull(client.getSession());

    SdkeyError err =
        assertThrows(SdkeyError.class, () -> client.validate("SDKY-TEST", "hwid-1"));
    assertEquals("VALIDATE_RESPONSE_INVALID", err.getCode());
    assertNull(client.getSession());
  }

  @Test
  void registerLoginAndUpgradeSendClientVersionAndOmitAbsentHwid() throws Exception {
    AtomicReference<String> registerBody = new AtomicReference<>();
    AtomicReference<String> loginBody = new AtomicReference<>();
    AtomicReference<String> upgradeBody = new AtomicReference<>();

    SdkeyHttpPost httpPost =
        (url, body) -> {
          String json = MAPPER.writeValueAsString(body);
          JsonNode el = MAPPER.readTree(json);

          assertEquals("1.2.3", el.get("clientVersion").asText());
          assertEquals("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", el.get("appId").asText());
          assertFalse(el.has("hwid"));

          if (url.endsWith("/api/v1/client/register")) {
            registerBody.set(json);
            assertEquals("player1", el.get("username").asText());
            assertEquals("password1", el.get("password").asText());
            return new SdkeyHttpPost.HttpResponse(201, toJsonNode(authSuccessBody(1)));
          }

          if (url.endsWith("/api/v1/client/login")) {
            loginBody.set(json);
            assertEquals("player1", el.get("username").asText());
            assertEquals("password1", el.get("password").asText());
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(authSuccessBody(1)));
          }

          if (url.endsWith("/api/v1/client/upgrade")) {
            upgradeBody.set(json);
            assertEquals("player1", el.get("username").asText());
            assertEquals("SDKY-NEW", el.get("licenseKey").asText());
            assertFalse(el.has("password"));
            return new SdkeyHttpPost.HttpResponse(200, toJsonNode(authSuccessBody(2)));
          }

          return new SdkeyHttpPost.HttpResponse(
              404, toJsonNode(Map.of("error", "not found")));
        };

    KeyPair keys = generateEd25519Pair();
    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .appVersion("1.2.3")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    ClientAuthResult registered =
        client.register(
            RegisterParams.builder()
                .username("player1")
                .password("password1")
                .licenseKey("SDKY-OLD")
                .build());
    assertEquals("tok", registered.getSessionToken());
    assertEquals(1, registered.getLicense().getSubscriptionTier());
    assertNotNull(registerBody.get());

    ClientAuthResult loggedIn =
        client.login(
            LoginParams.builder().username("player1").password("password1").build());
    assertEquals("player1", loggedIn.getUser().getUsername());
    assertNotNull(loginBody.get());

    ClientAuthResult upgraded =
        client.upgrade(
            UpgradeParams.builder().username("player1").licenseKey("SDKY-NEW").build());
    assertEquals(2, upgraded.getLicense().getSubscriptionTier());
    assertFalse(upgradeBody.get().contains("password"));
  }

  @Test
  void surfacesServerErrorAndCodeOnAuthFailure() {
    SdkeyHttpPost httpPost =
        (url, body) -> {
          Map<String, Object> response = new LinkedHashMap<>();
          response.put("success", false);
          response.put("error", "License tier must be higher than the current tier");
          response.put("code", "TIER_NOT_HIGHER");
          return new SdkeyHttpPost.HttpResponse(403, toJsonNode(response));
        };

    KeyPair keys = generateEd25519Pair();
    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl("https://api.example.test")
                .appId("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                .appVersion("1.0.0")
                .appPublicKeyB64(keys.publicKeyB64)
                .httpPost(httpPost)
                .build());

    SdkeyError err =
        assertThrows(
            SdkeyError.class,
            () ->
                client.upgrade(
                    UpgradeParams.builder()
                        .username("player1")
                        .licenseKey("SDKY-LOW")
                        .build()));
    assertEquals("AUTH_FAILED", err.getCode());
    assertEquals("License tier must be higher than the current tier", err.getMessage());
    assertEquals("TIER_NOT_HIGHER", err.getServerCode());
  }

  private static Map<String, Object> authSuccessBody(int tier) {
    Map<String, Object> user = new LinkedHashMap<>();
    user.put("id", "user-1");
    user.put("username", "player1");
    user.put("email", null);
    user.put("applicationId", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");

    Map<String, Object> license = new LinkedHashMap<>();
    license.put("id", "lic-1");
    license.put("status", "active");
    license.put("expiresAt", null);
    license.put("subscriptionTier", tier);

    Map<String, Object> session = new LinkedHashMap<>();
    session.put("ip", "203.0.113.1");
    session.put("hwid", null);

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("success", true);
    body.put("sessionToken", "tok");
    body.put("expiresAt", "2026-01-01T00:00:00.000Z");
    body.put("user", user);
    body.put("license", license);
    body.put("session", session);
    return body;
  }
}
