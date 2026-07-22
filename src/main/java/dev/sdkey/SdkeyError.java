package dev.sdkey;

/**
 * Protocol and transport errors for the SDKey client.
 */
public final class SdkeyError extends RuntimeException {
  private final String code;
  private final SdkeyErrorCode errorCode;
  private final String serverCode;

  public SdkeyError(SdkeyErrorCode errorCode, String message) {
    this(errorCode, message, null, null);
  }

  public SdkeyError(SdkeyErrorCode errorCode, String message, Throwable cause) {
    this(errorCode, message, cause, null);
  }

  public SdkeyError(SdkeyErrorCode errorCode, String message, String serverCode) {
    this(errorCode, message, null, serverCode);
  }

  public SdkeyError(
      SdkeyErrorCode errorCode, String message, Throwable cause, String serverCode) {
    super(message, cause);
    this.errorCode = errorCode;
    this.code = errorCode.toWireString();
    this.serverCode = serverCode;
  }

  /** SDK wire protocol error code (e.g. {@code HELLO_SIGNATURE_INVALID}). */
  public String getCode() {
    return code;
  }

  /** Typed protocol error code. */
  public SdkeyErrorCode getErrorCode() {
    return errorCode;
  }

  /** Server {@code code} from plaintext init/auth failure bodies, when present. */
  public String getServerCode() {
    return serverCode;
  }
}
