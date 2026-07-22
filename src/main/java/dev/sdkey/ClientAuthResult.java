package dev.sdkey;

/**
 * Success shape for register / login / upgrade (plaintext JSON). Failures throw {@link
 * SdkeyError} with server {@code error} / {@code code}.
 */
public final class ClientAuthResult {
  private final String sessionToken;
  private final String expiresAt;
  private final ClientAuthUser user;
  private final ClientAuthLicense license;
  private final ClientAuthSession session;

  public ClientAuthResult(
      String sessionToken,
      String expiresAt,
      ClientAuthUser user,
      ClientAuthLicense license,
      ClientAuthSession session) {
    this.sessionToken = sessionToken;
    this.expiresAt = expiresAt;
    this.user = user;
    this.license = license;
    this.session = session;
  }

  public String getSessionToken() {
    return sessionToken;
  }

  public String getExpiresAt() {
    return expiresAt;
  }

  public ClientAuthUser getUser() {
    return user;
  }

  public ClientAuthLicense getLicense() {
    return license;
  }

  public ClientAuthSession getSession() {
    return session;
  }
}
