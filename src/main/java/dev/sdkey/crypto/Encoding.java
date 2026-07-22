package dev.sdkey.crypto;

import java.util.Base64;

/**
 * Base64 helpers (standard and URL-safe).
 */
public final class Encoding {
  private Encoding() {}

  public static String bytesToBase64(byte[] data) {
    return Base64.getEncoder().encodeToString(data);
  }

  public static byte[] base64ToBytes(String b64) {
    String normalized = b64.replace('-', '+').replace('_', '/');
    int pad = normalized.length() % 4 == 0 ? 0 : 4 - (normalized.length() % 4);
    if (pad != 0) {
      normalized = normalized + "=".repeat(pad);
    }
    try {
      return Base64.getDecoder().decode(normalized);
    } catch (IllegalArgumentException ex) {
      throw new IllegalArgumentException("invalid base64", ex);
    }
  }
}
