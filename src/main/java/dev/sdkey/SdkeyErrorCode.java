package dev.sdkey;

/**
 * Protocol and transport error codes for {@link SdkeyError}.
 */
public enum SdkeyErrorCode {
  INIT_FAILED,
  HELLO_SIGNATURE_INVALID,
  VALIDATE_RESPONSE_INVALID,
  RESPONSE_SIGNATURE_INVALID,
  SESSION_MISMATCH,
  CLOCK_SKEW,
  AUTH_FAILED,
  NETWORK,
  UNKNOWN;

  public String toWireString() {
    return name();
  }

  public static SdkeyErrorCode fromWireString(String code) {
    if (code == null) {
      return UNKNOWN;
    }
    try {
      return SdkeyErrorCode.valueOf(code);
    } catch (IllegalArgumentException ex) {
      return UNKNOWN;
    }
  }
}
