package dev.sdkey.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Ed25519, HKDF session keys, and AES-GCM seal helpers.
 */
public final class Seal {
  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private Seal() {}

  /**
   * Sealed AES-GCM envelope fields used on the wire.
   */
  public static final class SealedEnvelope {
    private final String ivB64;
    private final String ciphertextB64;
    private final String tagB64;

    public SealedEnvelope(String ivB64, String ciphertextB64, String tagB64) {
      this.ivB64 = ivB64;
      this.ciphertextB64 = ciphertextB64;
      this.tagB64 = tagB64;
    }

    public String getIvB64() {
      return ivB64;
    }

    public String getCiphertextB64() {
      return ciphertextB64;
    }

    public String getTagB64() {
      return tagB64;
    }
  }

  /**
   * Import a raw 32-byte Ed25519 public key from base64.
   */
  public static Ed25519PublicKeyParameters importPublicKey(String publicKeyB64) {
    byte[] raw = Encoding.base64ToBytes(publicKeyB64);
    if (raw.length != 32) {
      throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
    }
    return new Ed25519PublicKeyParameters(raw, 0);
  }

  /**
   * Verify an Ed25519 signature over canonical JSON of {@code payload}.
   */
  public static boolean verifySignature(
      Ed25519PublicKeyParameters publicKey, Object payload, String signatureB64) {
    try {
      byte[] signature = Encoding.base64ToBytes(signatureB64);
      if (signature.length != 64) {
        return false;
      }
      byte[] message = CanonicalJson.canonicalJsonBytes(payload);
      Ed25519Signer signer = new Ed25519Signer();
      signer.init(false, publicKey);
      signer.update(message, 0, message.length);
      return signer.verifySignature(signature);
    } catch (RuntimeException ex) {
      return false;
    }
  }

  public static byte[] deriveSessionAesKey(
      byte[] clientNonce, byte[] serverNonce, String saltB64, String appId) {
    byte[] ikm = new byte[clientNonce.length + serverNonce.length];
    System.arraycopy(clientNonce, 0, ikm, 0, clientNonce.length);
    System.arraycopy(serverNonce, 0, ikm, clientNonce.length, serverNonce.length);

    byte[] salt = Encoding.base64ToBytes(saltB64);
    byte[] info =
        (Constants.SESSION_HKDF_INFO_PREFIX + appId).getBytes(StandardCharsets.UTF_8);

    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(ikm, salt, info));
    byte[] okm = new byte[Constants.SESSION_AES_KEY_BYTES];
    hkdf.generateBytes(okm, 0, okm.length);
    return okm;
  }

  public static SealedEnvelope sealAesGcm(byte[] aesKey, byte[] plaintext) {
    try {
      byte[] iv = new byte[Constants.AES_GCM_IV_BYTES];
      SECURE_RANDOM.nextBytes(iv);

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(Constants.AES_GCM_TAG_BITS, iv));
      byte[] ciphertextWithTag = cipher.doFinal(plaintext);

      int ciphertextLen = ciphertextWithTag.length - Constants.AES_GCM_TAG_BYTES;
      byte[] ciphertext = new byte[ciphertextLen];
      byte[] tag = new byte[Constants.AES_GCM_TAG_BYTES];
      System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLen);
      System.arraycopy(ciphertextWithTag, ciphertextLen, tag, 0, Constants.AES_GCM_TAG_BYTES);

      return new SealedEnvelope(
          Encoding.bytesToBase64(iv),
          Encoding.bytesToBase64(ciphertext),
          Encoding.bytesToBase64(tag));
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("AES-GCM seal failed", ex);
    }
  }

  public static byte[] openAesGcm(byte[] aesKey, SealedEnvelope envelope) {
    try {
      byte[] iv = Encoding.base64ToBytes(envelope.getIvB64());
      byte[] ciphertext = Encoding.base64ToBytes(envelope.getCiphertextB64());
      byte[] tag = Encoding.base64ToBytes(envelope.getTagB64());

      byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
      System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
      System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);

      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(aesKey, "AES"),
          new GCMParameterSpec(Constants.AES_GCM_TAG_BITS, iv));
      return cipher.doFinal(ciphertextWithTag);
    } catch (GeneralSecurityException ex) {
      throw new IllegalStateException("AES-GCM open failed", ex);
    }
  }
}
