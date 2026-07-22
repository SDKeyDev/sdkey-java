package dev.sdkey;

import java.net.http.HttpClient;

/**
 * Configuration for {@link SdkeyClient}.
 */
public final class SdkeyClientOptions {
  private final String apiBaseUrl;
  private final String appId;
  private final String appVersion;
  private final String appPublicKeyB64;
  private final SdkeyHttpPost httpPost;
  private final HttpClient httpClient;

  private SdkeyClientOptions(Builder builder) {
    this.apiBaseUrl = builder.apiBaseUrl;
    this.appId = builder.appId;
    this.appVersion = builder.appVersion;
    this.appPublicKeyB64 = builder.appPublicKeyB64;
    this.httpPost = builder.httpPost;
    this.httpClient = builder.httpClient;
  }

  public static Builder builder() {
    return new Builder();
  }

  public String getApiBaseUrl() {
    return apiBaseUrl;
  }

  public String getAppId() {
    return appId;
  }

  /**
   * Exact application version string. Sent as {@code clientVersion} on session init and
   * client-auth calls; must match {@code applications.version} or the server returns {@code
   * APP_OUTDATED}.
   */
  public String getAppVersion() {
    return appVersion;
  }

  public String getAppPublicKeyB64() {
    return appPublicKeyB64;
  }

  /** Optional transport override for tests or custom HTTP stacks. */
  public SdkeyHttpPost getHttpPost() {
    return httpPost;
  }

  /** Optional {@link HttpClient} used when {@link #getHttpPost()} is not set. */
  public HttpClient getHttpClient() {
    return httpClient;
  }

  public static final class Builder {
    private String apiBaseUrl;
    private String appId;
    private String appVersion;
    private String appPublicKeyB64;
    private SdkeyHttpPost httpPost;
    private HttpClient httpClient;

    public Builder apiBaseUrl(String apiBaseUrl) {
      this.apiBaseUrl = apiBaseUrl;
      return this;
    }

    public Builder appId(String appId) {
      this.appId = appId;
      return this;
    }

    public Builder appVersion(String appVersion) {
      this.appVersion = appVersion;
      return this;
    }

    public Builder appPublicKeyB64(String appPublicKeyB64) {
      this.appPublicKeyB64 = appPublicKeyB64;
      return this;
    }

    public Builder httpPost(SdkeyHttpPost httpPost) {
      this.httpPost = httpPost;
      return this;
    }

    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = httpClient;
      return this;
    }

    public SdkeyClientOptions build() {
      if (apiBaseUrl == null || apiBaseUrl.isBlank()) {
        throw new IllegalArgumentException("apiBaseUrl is required");
      }
      if (appId == null || appId.isBlank()) {
        throw new IllegalArgumentException("appId is required");
      }
      if (appVersion == null || appVersion.isBlank()) {
        throw new IllegalArgumentException("appVersion is required");
      }
      if (appPublicKeyB64 == null || appPublicKeyB64.isBlank()) {
        throw new IllegalArgumentException("appPublicKeyB64 is required");
      }
      return new SdkeyClientOptions(this);
    }
  }
}
