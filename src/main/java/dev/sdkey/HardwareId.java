package dev.sdkey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stable hardware ID helper for desktop clients.
 *
 * <p>Opt-in only — pass {@link #getHardwareId()} to {@link SdkeyClient#validate(String, String)} /
 * register / login / upgrade when binding a license to a machine. Omit for web clients.
 */
public final class HardwareId {
  private static final Path[] LINUX_MACHINE_ID_PATHS = {
    Path.of("/etc/machine-id"), Path.of("/var/lib/dbus/machine-id")
  };

  private static final Pattern WINDOWS_MACHINE_GUID =
      Pattern.compile("MachineGuid\\s+REG_SZ\\s+(\\S+)", Pattern.CASE_INSENSITIVE);

  private static final Pattern MACOS_PLATFORM_UUID =
      Pattern.compile("\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\"");

  private HardwareId() {}

  /**
   * Returns a SHA-256 hex digest of a stable OS machine identifier.
   *
   * <p>Reads a platform-specific machine ID, trims whitespace, hashes the UTF-8 bytes with
   * SHA-256, and returns lowercase hex (64 characters).
   *
   * @throws SdkeyError if the platform is unsupported or the machine ID is missing/empty
   */
  public static String getHardwareId() {
    return hashRawMachineId(readRawMachineId());
  }

  /** Package-visible for unit tests. */
  static String hashRawMachineId(String raw) {
    if (raw == null) {
      throw new SdkeyError(SdkeyErrorCode.HWID_UNAVAILABLE, "Machine identifier is empty");
    }
    String trimmed = raw.trim();
    if (trimmed.isEmpty()) {
      throw new SdkeyError(SdkeyErrorCode.HWID_UNAVAILABLE, "Machine identifier is empty");
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(trimmed.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(hash);
    } catch (NoSuchAlgorithmException ex) {
      throw new SdkeyError(
          SdkeyErrorCode.HWID_UNAVAILABLE, "SHA-256 is not available on this JVM", ex);
    }
  }

  /** Package-visible for unit tests. */
  static String readRawMachineId() {
    String os = System.getProperty("os.name", "");
    String normalized = os.toLowerCase(Locale.ROOT);
    if (normalized.contains("win")) {
      return readWindowsMachineGuid();
    }
    if (normalized.contains("linux")) {
      return readLinuxMachineId();
    }
    if (normalized.contains("mac")) {
      return readMacOsPlatformUuid();
    }
    throw new SdkeyError(
        SdkeyErrorCode.HWID_UNAVAILABLE,
        "Unsupported platform for hardware ID: " + (os.isEmpty() ? "unknown" : os));
  }

  private static String readWindowsMachineGuid() {
    ProcessBuilder builder =
        new ProcessBuilder(
            "reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid");
    builder.redirectErrorStream(true);
    try {
      Process process = builder.start();
      boolean finished = process.waitFor(10, TimeUnit.SECONDS);
      if (!finished) {
        process.destroyForcibly();
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE, "Timed out reading Windows MachineGuid");
      }
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      if (process.exitValue() != 0) {
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE,
            "Failed to read Windows MachineGuid from the registry");
      }
      Matcher matcher = WINDOWS_MACHINE_GUID.matcher(output);
      if (!matcher.find()) {
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE, "Windows MachineGuid not found in reg query output");
      }
      return matcher.group(1);
    } catch (SdkeyError ex) {
      throw ex;
    } catch (IOException | InterruptedException ex) {
      if (ex instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new SdkeyError(
          SdkeyErrorCode.HWID_UNAVAILABLE,
          "Failed to read Windows MachineGuid from the registry",
          ex);
    }
  }

  private static String readLinuxMachineId() {
    StringBuilder errors = new StringBuilder();
    for (Path path : LINUX_MACHINE_ID_PATHS) {
      try {
        return Files.readString(path, StandardCharsets.UTF_8);
      } catch (IOException ex) {
        if (errors.length() > 0) {
          errors.append("; ");
        }
        errors.append(path).append(": ").append(ex.getMessage());
      }
    }
    String detail = errors.length() > 0 ? errors.toString() : "no paths available";
    throw new SdkeyError(
        SdkeyErrorCode.HWID_UNAVAILABLE, "Failed to read Linux machine-id (" + detail + ")");
  }

  private static String readMacOsPlatformUuid() {
    ProcessBuilder builder =
        new ProcessBuilder("ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
    builder.redirectErrorStream(true);
    try {
      Process process = builder.start();
      boolean finished = process.waitFor(10, TimeUnit.SECONDS);
      if (!finished) {
        process.destroyForcibly();
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE, "Timed out reading IOPlatformUUID via ioreg");
      }
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      if (process.exitValue() != 0) {
        String detail = output.trim();
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE,
            "ioreg failed while reading IOPlatformUUID"
                + (detail.isEmpty() ? "" : ": " + detail));
      }
      Matcher matcher = MACOS_PLATFORM_UUID.matcher(output);
      if (!matcher.find()) {
        throw new SdkeyError(
            SdkeyErrorCode.HWID_UNAVAILABLE, "IOPlatformUUID not found in ioreg output");
      }
      return matcher.group(1);
    } catch (SdkeyError ex) {
      throw ex;
    } catch (IOException | InterruptedException ex) {
      if (ex instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      throw new SdkeyError(
          SdkeyErrorCode.HWID_UNAVAILABLE, "Failed to run ioreg for IOPlatformUUID", ex);
    }
  }
}
