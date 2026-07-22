package dev.sdkey.crypto;

import java.util.List;

/**
 * Wire-protocol constants (protocol v1).
 */
public final class Constants {
  public static final int PROTOCOL_VERSION = 1;

  public static final int CLOCK_SKEW_SECONDS = 60;

  public static final int CLIENT_NONCE_BYTES = 32;
  public static final int SERVER_NONCE_BYTES = 32;
  public static final int VALIDATE_NONCE_BYTES = 16;

  public static final int AES_GCM_IV_BYTES = 12;
  public static final int AES_GCM_TAG_BITS = 128;
  public static final int AES_GCM_TAG_BYTES = 16;
  public static final int SESSION_AES_KEY_BYTES = 32;

  public static final String SESSION_HKDF_INFO_PREFIX = "sdkey-session-v1";

  public static final List<String> VALIDATE_FAILURE_CODES =
      List.of(
          "SESSION_EXPIRED",
          "CLOCK_SKEW",
          "REPLAY",
          "LICENSE_NOT_FOUND",
          "APP_MISMATCH",
          "BANNED",
          "EXPIRED",
          "HWID_MISMATCH",
          "DECRYPT_FAIL",
          "APP_DISABLED",
          "APP_OUTDATED",
          "HWID_BANNED",
          "IP_BANNED");

  private Constants() {}
}
