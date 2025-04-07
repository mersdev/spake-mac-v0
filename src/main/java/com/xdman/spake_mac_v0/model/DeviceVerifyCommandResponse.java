package com.xdman.spake_mac_v0.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record DeviceVerifyCommandResponse(
  @JsonProperty("message")
  String spake2PlusVerifyResponse
) {
}
