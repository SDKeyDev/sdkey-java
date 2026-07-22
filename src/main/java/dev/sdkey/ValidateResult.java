package dev.sdkey;

/**
 * Result of a sealed license validate call.
 */
public final class ValidateResult {
  private final boolean success;
  private final String code;
  private final String message;
  private final String status;
  private final String expiresAt;
  private final Integer subscriptionTier;
  private final long timestamp;

  public ValidateResult(
      boolean success,
      String code,
      String message,
      String status,
      String expiresAt,
      Integer subscriptionTier,
      long timestamp) {
    this.success = success;
    this.code = code;
    this.message = message;
    this.status = status;
    this.expiresAt = expiresAt;
    this.subscriptionTier = subscriptionTier;
    this.timestamp = timestamp;
  }

  public boolean isSuccess() {
    return success;
  }

  public String getCode() {
    return code;
  }

  /** User-facing text from the sealed body ({@code message}, not {@code error}). */
  public String getMessage() {
    return message;
  }

  public String getStatus() {
    return status;
  }

  public String getExpiresAt() {
    return expiresAt;
  }

  /** Present on success (≥ 0); {@code null} on sealed failure. */
  public Integer getSubscriptionTier() {
    return subscriptionTier;
  }

  public long getTimestamp() {
    return timestamp;
  }
}
