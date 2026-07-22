# Sdkey

Official Java client for [SDKey](https://docs.sdkey.dev) license authentication.

Implements the sealed session protocol (Ed25519-verified handshake, HKDF session keys, AES-256-GCM validate) plus plaintext client auth (register / login / upgrade). See [PROTOCOL.md](./PROTOCOL.md).

## Install

Maven:

```xml
<dependency>
  <groupId>dev.sdkey</groupId>
  <artifactId>sdk</artifactId>
  <version>0.2.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("dev.sdkey:sdk:0.2.0")
```

Requires Java 17+.

## Quick start

Embed these values from the SDKey dashboard when you ship your app. **`appVersion` must exactly match** the application version configured in the dashboard (`applications.version`), or the server returns `APP_OUTDATED`.

```java
import dev.sdkey.*;

SdkeyClient client = new SdkeyClient(SdkeyClientOptions.builder()
    .apiBaseUrl("https://api.sdkey.dev")
    .appId("YOUR_APP_ID")
    .appVersion("1.0.0")
    .appPublicKeyB64("YOUR_APP_PUBLIC_KEY_BASE64")
    .build());

try {
    // HWID is optional — omit for web clients (JSON key is not sent).
    ValidateResult result = client.validate("SDKY-XXXX-XXXX-XXXX-XXXX", "machine-hwid");
    if (result.isSuccess()) {
        System.out.printf(
            "licensed %s tier=%s %s%n",
            result.getStatus(),
            result.getSubscriptionTier(),
            result.getExpiresAt());
        System.out.println(result.getMessage()); // e.g. "validated"
    } else {
        // Sealed validate failures use `message`, not `error`.
        System.err.printf("denied %s %s%n", result.getCode(), result.getMessage());
    }
} catch (SdkeyError err) {
    // Init / transport failures: getMessage() is server `error`; getServerCode() is server `code`.
    System.err.printf("%s %s serverCode=%s%n", err.getCode(), err.getMessage(), err.getServerCode());
    throw err;
}
```

`validate` calls `init` automatically when no session exists. Sessions last ~15 minutes server-side; on `SESSION_EXPIRED` the client clears local state so the next call re-handshakes.

### Client auth (register / login / upgrade)

These calls are **plaintext JSON** (not AES-sealed). They still send `appId` + `clientVersion`. Optional `hwid` follows the same omit-when-absent rules as validate.

```java
ClientAuthResult auth = client.register(RegisterParams.builder()
    .username("player1")
    .password("••••••••")
    .licenseKey("SDKY-XXXX-XXXX-XXXX-XXXX") // may be required by app settings
    .build());

auth = client.login(LoginParams.builder()
    .username("player1")
    .password("••••••••")
    .build());

// Upgrade = username + license key only (no password).
auth = client.upgrade(UpgradeParams.builder()
    .username("player1")
    .licenseKey("SDKY-HIGHER-TIER-KEY")
    .build());

System.out.println(auth.getSessionToken());
```

Auth failures throw `SdkeyError` with `getCode() = AUTH_FAILED`, `getMessage()` = server `error`, and `getServerCode()` = server `code`.

## Where `message` vs `error` appears

Per-app `responseMessages` can customize many strings. The SDK surfaces whatever the server returns.

| Surface | Success text field | Failure text field |
|---|---|---|
| Session init | *(none)* | `error` → `SdkeyError.getMessage()` (`getServerCode()` set) |
| Sealed validate | `message` (`ValidateResult.getMessage()`) | `message` (`ValidateResult.getMessage()`) |
| Client register/login/upgrade | *(none)* | `error` → `SdkeyError.getMessage()` (`getServerCode()` set) |

### Sealed validate success

```json
{
  "success": true,
  "code": "OK",
  "message": "validated",
  "status": "active",
  "expiresAt": "2026-01-01T00:00:00.000Z",
  "subscriptionTier": 0,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Sealed validate failure

```json
{
  "success": false,
  "code": "HWID_MISMATCH",
  "message": "Hardware ID mismatch",
  "status": null,
  "expiresAt": null,
  "sessionId": "...",
  "timestamp": 1720000001,
  "v": 1
}
```

### Init / auth failure (plaintext)

```json
{
  "success": false,
  "error": "Client version outdated",
  "code": "APP_OUTDATED"
}
```

## API

### `new SdkeyClient(SdkeyClientOptions)`

| Option | Type | Description |
|---|---|---|
| `apiBaseUrl` | `String` | API origin (no trailing slash) |
| `appId` | `String` | Application UUID |
| `appVersion` | `String` | Exact app version → sent as `clientVersion` |
| `appPublicKeyB64` | `String` | Raw Ed25519 public key (32 bytes), base64 |
| `httpPost` | `SdkeyHttpPost` | Optional HTTP POST override (tests / custom transport) |

### Methods

- `init()` — challenge handshake; verifies the signed hello; derives the AES session key
- `validate(licenseKey, hwid?)` — sealed validate; **always** decrypts then verifies the Ed25519 signature before trusting `success`
- `register(params)` / `login(params)` / `upgrade(params)` — plaintext `/api/v1/client/*`
- `getSession()` / `clearSession()` — inspect or drop the local crypto session

### Errors

Protocol / transport failures throw `SdkeyError` with a `getCode()`:

`INIT_FAILED` · `HELLO_SIGNATURE_INVALID` · `VALIDATE_RESPONSE_INVALID` · `RESPONSE_SIGNATURE_INVALID` · `SESSION_MISMATCH` · `CLOCK_SKEW` · `AUTH_FAILED` · `NETWORK`

License denials on sealed validate (banned, HWID mismatch, etc.) return a normal `ValidateResult` with `isSuccess() = false` — they are not thrown.

This package does **not** include developer tooling / Bearer management APIs.

## Security notes

- Never ship app **private** keys in a client.
- Do not skip signature verification — that is the anti-spoof binding.
- This package is open source; the SDKey server remains a separate product.

## Development

```bash
mvn test
mvn -q install
mvn -q -f examples/basic/pom.xml exec:java
```

## License

MIT
