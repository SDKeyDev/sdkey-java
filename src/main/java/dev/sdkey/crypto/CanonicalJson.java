package dev.sdkey.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Deterministic JSON encoding for Ed25519 signing. Object keys sorted lexicographically, no
 * insignificant whitespace.
 */
public final class CanonicalJson {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private CanonicalJson() {}

  public static String canonicalize(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof Boolean b) {
      return b ? "true" : "false";
    }
    if (value instanceof String s) {
      return quote(s);
    }
    if (value instanceof Number n) {
      return serializeNumber(n);
    }
    if (value instanceof JsonNode node) {
      return canonicalizeNode(node);
    }
    if (value instanceof Map<?, ?> map) {
      return canonicalizeMap(map);
    }
    if (value instanceof Iterable<?> iterable) {
      return canonicalizeIterable(iterable);
    }
    if (value.getClass().isArray()) {
      int length = java.lang.reflect.Array.getLength(value);
      List<Object> list = new ArrayList<>(length);
      for (int i = 0; i < length; i++) {
        list.add(java.lang.reflect.Array.get(value, i));
      }
      return canonicalizeIterable(list);
    }
    throw new IllegalArgumentException(
        "canonicalJson: unsupported type " + value.getClass().getName());
  }

  public static byte[] canonicalJsonBytes(Object value) {
    return canonicalize(value).getBytes(StandardCharsets.UTF_8);
  }

  private static String serializeNumber(Number value) {
    if (value instanceof Double d) {
      if (!Double.isFinite(d)) {
        throw new IllegalArgumentException("canonicalJson: non-finite numbers are not allowed");
      }
      return quoteNumber(d);
    }
    if (value instanceof Float f) {
      if (!Float.isFinite(f)) {
        throw new IllegalArgumentException("canonicalJson: non-finite numbers are not allowed");
      }
      return quoteNumber(f.doubleValue());
    }
    if (value instanceof Long
        || value instanceof Integer
        || value instanceof Short
        || value instanceof Byte) {
      return Long.toString(value.longValue());
    }
    // BigDecimal / other — emit via Jackson for consistency
    try {
      return MAPPER.writeValueAsString(value);
    } catch (JsonProcessingException ex) {
      throw new IllegalArgumentException("canonicalJson: failed to serialize number", ex);
    }
  }

  private static String quoteNumber(double d) {
    try {
      return MAPPER.writeValueAsString(d);
    } catch (JsonProcessingException ex) {
      throw new IllegalArgumentException("canonicalJson: failed to serialize number", ex);
    }
  }

  private static String quote(String s) {
    try {
      return MAPPER.writeValueAsString(s);
    } catch (JsonProcessingException ex) {
      throw new IllegalArgumentException("canonicalJson: failed to serialize string", ex);
    }
  }

  private static String canonicalizeNode(JsonNode node) {
    if (node == null || node.isNull()) {
      return "null";
    }
    if (node.isBoolean()) {
      return node.booleanValue() ? "true" : "false";
    }
    if (node.isTextual()) {
      return quote(node.textValue());
    }
    if (node.isNumber()) {
      return node.asText();
    }
    if (node.isArray()) {
      ArrayNode array = (ArrayNode) node;
      StringBuilder sb = new StringBuilder();
      sb.append('[');
      for (int i = 0; i < array.size(); i++) {
        if (i > 0) {
          sb.append(',');
        }
        sb.append(canonicalizeNode(array.get(i)));
      }
      sb.append(']');
      return sb.toString();
    }
    if (node.isObject()) {
      ObjectNode object = (ObjectNode) node;
      TreeMap<String, JsonNode> sorted = new TreeMap<>();
      Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
      while (fields.hasNext()) {
        Map.Entry<String, JsonNode> entry = fields.next();
        sorted.put(entry.getKey(), entry.getValue());
      }
      StringBuilder sb = new StringBuilder();
      sb.append('{');
      boolean first = true;
      for (Map.Entry<String, JsonNode> entry : sorted.entrySet()) {
        if (!first) {
          sb.append(',');
        }
        first = false;
        sb.append(quote(entry.getKey()));
        sb.append(':');
        sb.append(canonicalizeNode(entry.getValue()));
      }
      sb.append('}');
      return sb.toString();
    }
    throw new IllegalArgumentException("canonicalJson: unsupported JsonNode " + node.getNodeType());
  }

  private static String canonicalizeMap(Map<?, ?> map) {
    TreeMap<String, Object> sorted = new TreeMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new IllegalArgumentException("canonicalJson: map keys must be strings");
      }
      sorted.put(key, entry.getValue());
    }
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    boolean first = true;
    for (Map.Entry<String, Object> entry : sorted.entrySet()) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append(quote(entry.getKey()));
      sb.append(':');
      sb.append(canonicalize(entry.getValue()));
    }
    sb.append('}');
    return sb.toString();
  }

  private static String canonicalizeIterable(Iterable<?> iterable) {
    StringBuilder sb = new StringBuilder();
    sb.append('[');
    boolean first = true;
    for (Object item : iterable) {
      if (!first) {
        sb.append(',');
      }
      first = false;
      sb.append(canonicalize(item));
    }
    sb.append(']');
    return sb.toString();
  }
}
