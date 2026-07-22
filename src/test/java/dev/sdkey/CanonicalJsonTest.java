package dev.sdkey;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.sdkey.crypto.CanonicalJson;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CanonicalJsonTest {
  @Test
  void sortsObjectKeysLexicographically() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("b", 1);
    map.put("a", 2);
    assertEquals("{\"a\":2,\"b\":1}", CanonicalJson.canonicalize(map));
  }

  @Test
  void encodesNullFields() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("a", 1);
    map.put("b", null);
    assertEquals("{\"a\":1,\"b\":null}", CanonicalJson.canonicalize(map));
  }

  @Test
  void encodesNestedStructuresWithoutWhitespace() {
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("k", 0);
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("z", Arrays.asList(true, null, "x"));
    map.put("m", nested);
    assertEquals("{\"m\":{\"k\":0},\"z\":[true,null,\"x\"]}", CanonicalJson.canonicalize(map));
  }

  @Test
  void returnsUtf8Bytes() {
    Map<String, Object> map = Map.of("a", 1);
    byte[] bytes = CanonicalJson.canonicalJsonBytes(map);
    assertEquals("{\"a\":1}", new String(bytes, StandardCharsets.UTF_8));
  }
}
