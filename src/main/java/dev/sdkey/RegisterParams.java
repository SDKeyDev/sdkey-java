package dev.sdkey;

/** Parameters for {@link SdkeyClient#register(RegisterParams)}. */
public final class RegisterParams {
  private final String username;
  private final String password;
  private final String email;
  private final String licenseKey;
  private final String hwid;

  private RegisterParams(Builder builder) {
    this.username = builder.username;
    this.password = builder.password;
    this.email = builder.email;
    this.licenseKey = builder.licenseKey;
    this.hwid = builder.hwid;
  }

  public static Builder builder() {
    return new Builder();
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }

  public String getEmail() {
    return email;
  }

  public String getLicenseKey() {
    return licenseKey;
  }

  public String getHwid() {
    return hwid;
  }

  public static final class Builder {
    private String username;
    private String password;
    private String email;
    private String licenseKey;
    private String hwid;

    public Builder username(String username) {
      this.username = username;
      return this;
    }

    public Builder password(String password) {
      this.password = password;
      return this;
    }

    public Builder email(String email) {
      this.email = email;
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

    public RegisterParams build() {
      if (username == null || username.isBlank()) {
        throw new IllegalArgumentException("username is required");
      }
      if (password == null || password.isBlank()) {
        throw new IllegalArgumentException("password is required");
      }
      return new RegisterParams(this);
    }
  }
}
