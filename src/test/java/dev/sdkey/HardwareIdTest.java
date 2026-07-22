package dev.sdkey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

class HardwareIdTest {
  @Test
  void hashesTrimmedUtf8BytesAsLowercaseSha256Hex() throws Exception {
    String raw = "  fixture-machine-id\n";
    String expected =
        HexFormat.of()
            .formatHex(
                MessageDigest.getInstance("SHA-256")
                    .digest("fixture-machine-id".getBytes(StandardCharsets.UTF_8)));

    assertEquals(expected, HardwareId.hashRawMachineId(raw));
    assertEquals(64, expected.length());
    assertEquals(expected, expected.toLowerCase(Locale.ROOT));
  }

  @Test
  void rejectsNullAndBlankRawIds() {
    SdkeyError nullErr =
        assertThrows(SdkeyError.class, () -> HardwareId.hashRawMachineId(null));
    assertEquals(SdkeyErrorCode.HWID_UNAVAILABLE, nullErr.getErrorCode());
    assertTrue(nullErr.getMessage().toLowerCase(Locale.ROOT).contains("empty"));

    SdkeyError blankErr =
        assertThrows(SdkeyError.class, () -> HardwareId.hashRawMachineId("   \n\t  "));
    assertEquals(SdkeyErrorCode.HWID_UNAVAILABLE, blankErr.getErrorCode());
    assertTrue(blankErr.getMessage().toLowerCase(Locale.ROOT).contains("empty"));
  }

  @Test
  @EnabledOnOs(OS.WINDOWS)
  void readsAndHashesWindowsMachineGuid() {
    String hwid = HardwareId.getHardwareId();
    assertEquals(64, hwid.length());
    assertTrue(hwid.matches("[0-9a-f]{64}"));

    String raw = HardwareId.readRawMachineId().trim();
    assertEquals(HardwareId.hashRawMachineId(raw), hwid);
  }
}
