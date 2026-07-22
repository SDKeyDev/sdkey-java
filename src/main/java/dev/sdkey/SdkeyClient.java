package dev.sdkey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import dev.sdkey.crypto.Constants;
import dev.sdkey.crypto.Encoding;
import dev.sdkey.crypto.Seal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

/**
 * SDKey license client. Flow: {@link #init()} (session handshake) → {@link #validate(String,
 * String)} (sealed request). {@link #validate(String, String)} calls {@link #init()}
 * automatically when no session exists. Also exposes plaintext client auth: {@link
 * #register(RegisterParams)}, {@link #login(LoginParams)}, {@link #upgrade(UpgradeParams)}.
 */
public final class SdkeyClient implements AutoCloseable {
  private static final ObjectMapper MAPPER =
      new ObjectMapper()
          .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, false)
          .setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final String apiBaseUrl;
  private final String appId;
  private final String appVersion;
  private final String appPublicKeyB64;
  private final SdkeyHttpPost httpPost;
  private final HttpClient httpClient;

  private Ed25519PublicKeyParameters publicKey;
  private SessionState session;

  public SdkeyClient(SdkeyClientOptions options) {
    Objects.requireNonNull(options, "options");
    this.apiBaseUrl = options.getApiBaseUrl().replaceAll("/+$", "");
    this.appId = options.getAppId();
    this.appVersion = options.getAppVersion();
    this.appPublicKeyB64 = options.getAppPublicKeyB64();

    if (options.getHttpPost() != null) {
      this.httpPost = options.getHttpPost();
      this.httpClient = null;
    } else {
      this.httpClient =
          options.getHttpClient() != null ? options.getHttpClient() : HttpClient.newHttpClient();
      this.httpPost = this::defaultHttpPost;
    }
  }

  /** Active session, if any. */
  public SessionState getSession() {
    return session;
  }

  /** Drop the current session (next {@link #validate(String, String)} will re-init). */
  public void clearSession() {
    session = null;
  }

  public SessionState init() {
    publicKey = Seal.importPublicKey(appPublicKeyB64);
    byte[] clientNonce = new byte[Constants.CLIENT_NONCE_BYTES];
    SECURE_RANDOM.nextBytes(clientNonce);

    SdkeyHttpPost.HttpResponse response;
    try {
      Map<String, Object> body = new LinkedHashMap<>();
      body.put("appId", appId);
      body.put("clientNonceB64", Encoding.bytesToBase64(clientNonce));
      body.put("clientVersion", appVersion);
      response = httpPost.post(apiBaseUrl + "/api/v1/session/init", body);
    } catch (SdkeyError ex) {
      throw ex;
    } catch (Exception ex) {
      throw new SdkeyError(SdkeyErrorCode.NETWORK, "session init request failed", ex);
    }

    JsonNode body = response.body();
    boolean success =
        body != null && body.isObject() && body.path("success").asBoolean(false);

    if (response.statusCode() < 200 || response.statusCode() >= 300 || !success) {
      String error = optionalText(body, "error");
      if (error == null) {
        error = "session init failed";
      }
      throw new SdkeyError(
          SdkeyErrorCode.INIT_FAILED, error, optionalText(body, "code"));
    }

    String sessionId = requiredText(body, "sessionId", SdkeyErrorCode.INIT_FAILED);
    String serverNonceB64 = requiredText(body, "serverNonceB64", SdkeyErrorCode.INIT_FAILED);
    String hkdfSaltB64 = requiredText(body, "hkdfSaltB64", SdkeyErrorCode.INIT_FAILED);
    if (!body.has("timestamp") || !body.get("timestamp").canConvertToLong()) {
      throw new SdkeyError(SdkeyErrorCode.INIT_FAILED, "missing timestamp");
    }
    long timestamp = body.get("timestamp").asLong();
    String signatureB64 = requiredText(body, "signatureB64", SdkeyErrorCode.INIT_FAILED);

    Map<String, Object> hello = new LinkedHashMap<>();
    hello.put("appId", appId);
    hello.put("hkdfSaltB64", hkdfSaltB64);
    hello.put("serverNonceB64", serverNonceB64);
    hello.put("sessionId", sessionId);
    hello.put("timestamp", timestamp);
    hello.put("v", Constants.PROTOCOL_VERSION);

    if (!Seal.verifySignature(publicKey, hello, signatureB64)) {
      throw new SdkeyError(
          SdkeyErrorCode.HELLO_SIGNATURE_INVALID, "hello signature verification failed");
    }

    byte[] aesKey =
        Seal.deriveSessionAesKey(
            clientNonce, Encoding.base64ToBytes(serverNonceB64), hkdfSaltB64, appId);

    session = new SessionState(sessionId, aesKey, serverNonceB64, hkdfSaltB64);
    return session;
  }

  /**
   * Sealed license validate. {@code hwid} is optional; when omitted the JSON key is not sent (web
   * clients).
   */
  public ValidateResult validate(String licenseKey) {
    return validate(licenseKey, null);
  }

  /**
   * Sealed license validate. {@code hwid} is optional; when omitted the JSON key is not sent (web
   * clients).
   */
  public ValidateResult validate(String licenseKey, String hwid) {
    if (session == null || publicKey == null) {
      init();
    }

    SessionState active = session;
    Ed25519PublicKeyParameters key = publicKey;

    byte[] validateNonce = new byte[Constants.VALIDATE_NONCE_BYTES];
    SECURE_RANDOM.nextBytes(validateNonce);

    Map<String, Object> inner = new LinkedHashMap<>();
    inner.put("licenseKey", licenseKey);
    inner.put("nonce", Encoding.bytesToBase64(validateNonce));
    inner.put("timestamp", Instant.now().getEpochSecond());
    inner.put("v", Constants.PROTOCOL_VERSION);
    if (hwid != null && !hwid.isEmpty()) {
      inner.put("hwid", hwid);
    }

    String innerJson;
    try {
      innerJson = MAPPER.writeValueAsString(inner);
    } catch (Exception ex) {
      throw new SdkeyError(SdkeyErrorCode.VALIDATE_RESPONSE_INVALID, "failed to serialize validate payload", ex);
    }

    Seal.SealedEnvelope sealedEnvelope =
        Seal.sealAesGcm(active.aesKeyInternal(), innerJson.getBytes(StandardCharsets.UTF_8));

    SdkeyHttpPost.HttpResponse response;
    try {
      Map<String, Object> requestBody = new LinkedHashMap<>();
      requestBody.put("sessionId", active.getSessionId());
      requestBody.put("ivB64", sealedEnvelope.getIvB64());
      requestBody.put("ciphertextB64", sealedEnvelope.getCiphertextB64());
      requestBody.put("tagB64", sealedEnvelope.getTagB64());
      response = httpPost.post(apiBaseUrl + "/api/v1/licenses/validate", requestBody);
    } catch (SdkeyError ex) {
      throw ex;
    } catch (Exception ex) {
      throw new SdkeyError(SdkeyErrorCode.NETWORK, "validate request failed", ex);
    }

    JsonNode envelope = response.body();
    String ivB64 = optionalText(envelope, "ivB64");
    String ciphertextB64 = optionalText(envelope, "ciphertextB64");
    String tagB64 = optionalText(envelope, "tagB64");
    String signatureB64 = optionalText(envelope, "signatureB64");

    if (ivB64 == null || ciphertextB64 == null || tagB64 == null || signatureB64 == null) {
      if ("SESSION_EXPIRED".equals(optionalText(envelope, "code"))) {
        clearSession();
      }
      String error = optionalText(envelope, "error");
      if (error == null) {
        error = "invalid validate response";
      }
      throw new SdkeyError(
          SdkeyErrorCode.VALIDATE_RESPONSE_INVALID,
          error,
          optionalText(envelope, "code"));
    }

    byte[] plainBytes;
    try {
      plainBytes =
          Seal.openAesGcm(
              active.aesKeyInternal(), new Seal.SealedEnvelope(ivB64, ciphertextB64, tagB64));
    } catch (Exception ex) {
      throw new SdkeyError(
          SdkeyErrorCode.VALIDATE_RESPONSE_INVALID, "failed to decrypt validate response", ex);
    }

    JsonNode plaintext;
    try {
      plaintext = MAPPER.readTree(plainBytes);
    } catch (Exception ex) {
      throw new SdkeyError(
          SdkeyErrorCode.VALIDATE_RESPONSE_INVALID, "invalid validate plaintext JSON", ex);
    }

    if (!Seal.verifySignature(key, plaintext, signatureB64)) {
      throw new SdkeyError(
          SdkeyErrorCode.RESPONSE_SIGNATURE_INVALID, "response signature verification failed");
    }

    String responseSessionId = optionalText(plaintext, "sessionId");
    if (!Objects.equals(responseSessionId, active.getSessionId())) {
      throw new SdkeyError(SdkeyErrorCode.SESSION_MISMATCH, "sessionId mismatch");
    }

    if (!plaintext.has("timestamp") || !plaintext.get("timestamp").canConvertToLong()) {
      throw new SdkeyError(SdkeyErrorCode.VALIDATE_RESPONSE_INVALID, "missing timestamp");
    }
    long ts = plaintext.get("timestamp").asLong();
    long now = Instant.now().getEpochSecond();
    if (Math.abs(now - ts) > Constants.CLOCK_SKEW_SECONDS) {
      throw new SdkeyError(SdkeyErrorCode.CLOCK_SKEW, "response clock skew");
    }

    String code = optionalText(plaintext, "code");
    if (code == null) {
      code = "";
    }
    if ("SESSION_EXPIRED".equals(code)) {
      clearSession();
    }

    String message = optionalText(plaintext, "message");
    if (message == null) {
      message = "";
    }
    boolean success = plaintext.path("success").asBoolean(false);
    String status = optionalText(plaintext, "status");
    String expiresAt = optionalText(plaintext, "expiresAt");
    Integer subscriptionTier = optionalInt(plaintext, "subscriptionTier");

    return new ValidateResult(success, code, message, status, expiresAt, subscriptionTier, ts);
  }

  /** Register a user via plaintext {@code POST /api/v1/client/register}. */
  public ClientAuthResult register(RegisterParams parameters) {
    Objects.requireNonNull(parameters, "parameters");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("appId", appId);
    body.put("username", parameters.getUsername());
    body.put("password", parameters.getPassword());
    body.put("clientVersion", appVersion);
    if (parameters.getEmail() != null && !parameters.getEmail().isEmpty()) {
      body.put("email", parameters.getEmail());
    }
    if (parameters.getLicenseKey() != null && !parameters.getLicenseKey().isEmpty()) {
      body.put("licenseKey", parameters.getLicenseKey());
    }
    if (parameters.getHwid() != null && !parameters.getHwid().isEmpty()) {
      body.put("hwid", parameters.getHwid());
    }
    return clientAuth("register", body);
  }

  /** Log in via plaintext {@code POST /api/v1/client/login}. */
  public ClientAuthResult login(LoginParams parameters) {
    Objects.requireNonNull(parameters, "parameters");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("appId", appId);
    body.put("username", parameters.getUsername());
    body.put("password", parameters.getPassword());
    body.put("clientVersion", appVersion);
    if (parameters.getHwid() != null && !parameters.getHwid().isEmpty()) {
      body.put("hwid", parameters.getHwid());
    }
    return clientAuth("login", body);
  }

  /**
   * Upgrade the user's linked license via plaintext {@code POST /api/v1/client/upgrade}. Sends
   * username + license key only (no password).
   */
  public ClientAuthResult upgrade(UpgradeParams parameters) {
    Objects.requireNonNull(parameters, "parameters");
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("appId", appId);
    body.put("username", parameters.getUsername());
    body.put("licenseKey", parameters.getLicenseKey());
    body.put("clientVersion", appVersion);
    if (parameters.getHwid() != null && !parameters.getHwid().isEmpty()) {
      body.put("hwid", parameters.getHwid());
    }
    return clientAuth("upgrade", body);
  }

  @Override
  public void close() {
    // HttpClient is not AutoCloseable on all JDKs; nothing to dispose for default client.
  }

  private ClientAuthResult clientAuth(String path, Map<String, Object> body) {
    SdkeyHttpPost.HttpResponse response;
    try {
      response = httpPost.post(apiBaseUrl + "/api/v1/client/" + path, body);
    } catch (SdkeyError ex) {
      throw ex;
    } catch (Exception ex) {
      throw new SdkeyError(SdkeyErrorCode.NETWORK, "client " + path + " request failed", ex);
    }

    JsonNode json = response.body();
    boolean success =
        json != null && json.isObject() && json.path("success").asBoolean(false);

    if (response.statusCode() < 200 || response.statusCode() >= 300 || !success) {
      String error = optionalText(json, "error");
      if (error == null) {
        error = "client " + path + " failed";
      }
      throw new SdkeyError(SdkeyErrorCode.AUTH_FAILED, error, optionalText(json, "code"));
    }

    String sessionToken = requiredText(json, "sessionToken", SdkeyErrorCode.AUTH_FAILED);
    String expiresAt = requiredText(json, "expiresAt", SdkeyErrorCode.AUTH_FAILED);

    JsonNode userEl = json.get("user");
    if (userEl == null || !userEl.isObject()) {
      throw new SdkeyError(SdkeyErrorCode.AUTH_FAILED, "missing user");
    }
    ClientAuthUser user =
        new ClientAuthUser(
            requiredText(userEl, "id", SdkeyErrorCode.AUTH_FAILED),
            requiredText(userEl, "username", SdkeyErrorCode.AUTH_FAILED),
            optionalText(userEl, "email"),
            requiredText(userEl, "applicationId", SdkeyErrorCode.AUTH_FAILED));

    ClientAuthLicense license = null;
    JsonNode licenseEl = json.get("license");
    if (licenseEl != null && licenseEl.isObject()) {
      Integer tier = optionalInt(licenseEl, "subscriptionTier");
      license =
          new ClientAuthLicense(
              requiredText(licenseEl, "id", SdkeyErrorCode.AUTH_FAILED),
              requiredText(licenseEl, "status", SdkeyErrorCode.AUTH_FAILED),
              optionalText(licenseEl, "expiresAt"),
              tier != null ? tier : 0);
    }

    JsonNode sessionEl = json.get("session");
    if (sessionEl == null || !sessionEl.isObject()) {
      throw new SdkeyError(SdkeyErrorCode.AUTH_FAILED, "missing session");
    }
    ClientAuthSession authSession =
        new ClientAuthSession(
            requiredText(sessionEl, "ip", SdkeyErrorCode.AUTH_FAILED),
            optionalText(sessionEl, "hwid"));

    return new ClientAuthResult(sessionToken, expiresAt, user, license, authSession);
  }

  private SdkeyHttpPost.HttpResponse defaultHttpPost(String url, Object body) throws Exception {
    String json = MAPPER.writeValueAsString(body);
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
            .build();

    HttpResponse<String> response =
        httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    String raw = response.body();
    if (raw == null || raw.isEmpty()) {
      return new SdkeyHttpPost.HttpResponse(response.statusCode(), MAPPER.nullNode());
    }
    try {
      return new SdkeyHttpPost.HttpResponse(response.statusCode(), MAPPER.readTree(raw));
    } catch (Exception ex) {
      return new SdkeyHttpPost.HttpResponse(response.statusCode(), MAPPER.nullNode());
    }
  }

  private static String optionalText(JsonNode element, String name) {
    if (element == null || !element.isObject() || !element.has(name) || element.get(name).isNull()) {
      return null;
    }
    JsonNode prop = element.get(name);
    if (prop.isTextual()) {
      return prop.asText();
    }
    return prop.asText();
  }

  private static Integer optionalInt(JsonNode element, String name) {
    if (element == null
        || !element.isObject()
        || !element.has(name)
        || !element.get(name).isNumber()) {
      return null;
    }
    return element.get(name).asInt();
  }

  private static String requiredText(JsonNode element, String name, SdkeyErrorCode code) {
    String value = optionalText(element, name);
    if (value == null) {
      throw new SdkeyError(code, "missing " + name);
    }
    return value;
  }
}
