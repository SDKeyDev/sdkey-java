package dev.sdkey;

/** Parameters for {@link SdkeyClient#login(LoginParams)}. */
public final class LoginParams {
  private final String username;
  private final String password;
  private final String hwid;

  private LoginParams(Builder builder) {
    this.username = builder.username;
    this.password = builder.password;
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

  public String getHwid() {
    return hwid;
  }

  public static final class Builder {
    private String username;
    private String password;
    private String hwid;

    public Builder username(String username) {
      this.username = username;
      return this;
    }

    public Builder password(String password) {
      this.password = password;
      return this;
    }

    public Builder hwid(String hwid) {
      this.hwid = hwid;
      return this;
    }

    public LoginParams build() {
      if (username == null || username.isBlank()) {
        throw new IllegalArgumentException("username is required");
      }
      if (password == null || password.isBlank()) {
        throw new IllegalArgumentException("password is required");
      }
      return new LoginParams(this);
    }
  }
}
