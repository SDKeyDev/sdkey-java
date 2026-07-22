package dev.sdkey;

/**
 * Parameters for {@link SdkeyClient#upgrade(UpgradeParams)}. Username + license key only (no
 * password).
 */
public final class UpgradeParams {
  private final String username;
  private final String licenseKey;
  private final String hwid;

  private UpgradeParams(Builder builder) {
    this.username = builder.username;
    this.licenseKey = builder.licenseKey;
    this.hwid = builder.hwid;
  }

  public static Builder builder() {
    return new Builder();
  }

  public String getUsername() {
    return username;
  }

  public String getLicenseKey() {
    return licenseKey;
  }

  public String getHwid() {
    return hwid;
  }

  public static final class Builder {
    private String username;
    private String licenseKey;
    private String hwid;

    public Builder username(String username) {
      this.username = username;
      return this;
    }

    public Builder licenseKey(String licenseKey) {
      this.licenseKey = licenseKey;
      return this;
    }

    public Builder hwid(String hwid) {
      this.hwid = hwid;
      return this;
    }

    public UpgradeParams build() {
      if (username == null || username.isBlank()) {
        throw new IllegalArgumentException("username is required");
      }
      if (licenseKey == null || licenseKey.isBlank()) {
        throw new IllegalArgumentException("licenseKey is required");
      }
      return new UpgradeParams(this);
    }
  }
}
