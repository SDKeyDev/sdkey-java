package dev.sdkey;

/** License object returned by register / login / upgrade when linked. */
public final class ClientAuthLicense {
  private final String id;
  private final String status;
  private final String expiresAt;
  private final int subscriptionTier;

  public ClientAuthLicense(String id, String status, String expiresAt, int subscriptionTier) {
    this.id = id;
    this.status = status;
    this.expiresAt = expiresAt;
    this.subscriptionTier = subscriptionTier;
  }

  public String getId() {
    return id;
  }

  public String getStatus() {
    return status;
  }

  public String getExpiresAt() {
    return expiresAt;
  }

  public int getSubscriptionTier() {
    return subscriptionTier;
  }
}
