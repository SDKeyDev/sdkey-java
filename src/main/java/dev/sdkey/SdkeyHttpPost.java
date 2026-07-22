package dev.sdkey;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Optional HTTP POST override: {@code (url, jsonBody) -> (statusCode, responseJson)}.
 */
@FunctionalInterface
public interface SdkeyHttpPost {
  HttpResponse post(String url, Object body) throws Exception;

  /** Status code + parsed JSON body from an HTTP POST. */
  record HttpResponse(int statusCode, JsonNode body) {}
}
