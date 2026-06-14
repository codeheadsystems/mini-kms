package com.codeheadsystems.minikms.protocol;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Serializes and parses the newline-delimited JSON wire protocol.
 *
 * <p>Each request/response is one JSON object encoded on a single line; the
 * newline framing is the transport's concern, not this codec's. This class
 * produces compact single-line JSON (no embedded newlines) and parses one object
 * from a string.
 *
 * <p>Thread-safe: the underlying {@link ObjectMapper} is configured once and only
 * read afterwards.
 */
public final class ProtocolCodec {

  private final ObjectMapper mapper;

  /** Create a codec with a strict-but-tolerant mapper. */
  public ProtocolCodec() {
    this.mapper = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  /**
   * @param request the request to serialize.
   * @return single-line JSON (no trailing newline).
   */
  public String encodeRequest(final KmsRequest request) {
    return write(request);
  }

  /**
   * @param response the response to serialize.
   * @return single-line JSON (no trailing newline).
   */
  public String encodeResponse(final KmsResponse response) {
    return write(response);
  }

  /**
   * @param line one JSON object line.
   * @return the parsed request.
   * @throws ProtocolException if the line is not a valid request object.
   */
  public KmsRequest decodeRequest(final String line) {
    try {
      return mapper.readValue(line, KmsRequest.class);
    } catch (final JsonProcessingException e) {
      throw new ProtocolException("malformed request JSON");
    } catch (final IllegalArgumentException e) {
      throw new ProtocolException(e.getMessage());
    }
  }

  /**
   * @param line one JSON object line.
   * @return the parsed response.
   * @throws ProtocolException if the line is not a valid response object.
   */
  public KmsResponse decodeResponse(final String line) {
    try {
      return mapper.readValue(line, KmsResponse.class);
    } catch (final JsonProcessingException e) {
      throw new ProtocolException("malformed response JSON");
    }
  }

  private String write(final Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (final JsonProcessingException e) {
      throw new ProtocolException("failed to serialize protocol object");
    }
  }
}
