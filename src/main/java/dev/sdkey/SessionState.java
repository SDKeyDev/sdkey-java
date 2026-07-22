package dev.sdkey;

/**
 * Active sealed-session state after a successful init handshake.
 */
public final class SessionState {
  private final String sessionId;
  private final byte[] aesKey;
  private final String serverNonceB64;
  private final String hkdfSaltB64;

  public SessionState(
      String sessionId, byte[] aesKey, String serverNonceB64, String hkdfSaltB64) {
    this.sessionId = sessionId;
    this.aesKey = aesKey.clone();
    this.serverNonceB64 = serverNonceB64;
    this.hkdfSaltB64 = hkdfSaltB64;
  }

  public String getSessionId() {
    return sessionId;
  }

  public byte[] getAesKey() {
    return aesKey.clone();
  }

  /** Package-private access for sealing without an extra clone. */
  byte[] aesKeyInternal() {
    return aesKey;
  }

  public String getServerNonceB64() {
    return serverNonceB64;
  }

  public String getHkdfSaltB64() {
    return hkdfSaltB64;
  }
}
