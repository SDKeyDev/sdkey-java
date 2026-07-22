/**
 * Minimal usage example. Replace placeholders with values from the SDKey dashboard.
 *
 * <pre>
 *   mvn -q -f examples/basic/pom.xml exec:java
 * </pre>
 */
package dev.sdkey.example;

import dev.sdkey.SdkeyClient;
import dev.sdkey.SdkeyClientOptions;
import dev.sdkey.SdkeyError;
import dev.sdkey.ValidateResult;

public final class BasicExample {
  public static void main(String[] args) {
    SdkeyClient client =
        new SdkeyClient(
            SdkeyClientOptions.builder()
                .apiBaseUrl(env("SDKEY_API_BASE_URL", "https://api.sdkey.dev"))
                .appId(env("SDKEY_APP_ID", "00000000-0000-0000-0000-000000000000"))
                .appVersion(env("SDKEY_APP_VERSION", "1.0.0"))
                .appPublicKeyB64(env("SDKEY_APP_PUBLIC_KEY_B64", ""))
                .build());

    String licenseKey = env("SDKEY_LICENSE_KEY", "SDKY-XXXX-XXXX-XXXX-XXXX");
    String hwid = System.getenv("SDKEY_HWID"); // optional — omit for web

    try {
      ValidateResult result = client.validate(licenseKey, hwid);
      System.out.printf(
          "success=%s code=%s message=%s status=%s tier=%s expiresAt=%s%n",
          result.isSuccess(),
          result.getCode(),
          result.getMessage(),
          result.getStatus(),
          result.getSubscriptionTier(),
          result.getExpiresAt());
    } catch (SdkeyError err) {
      System.err.printf(
          "[%s] %s serverCode=%s%n", err.getCode(), err.getMessage(), err.getServerCode());
      System.exit(1);
    }
  }

  private static String env(String name, String fallback) {
    String value = System.getenv(name);
    return value == null || value.isEmpty() ? fallback : value;
  }

  private BasicExample() {}
}
