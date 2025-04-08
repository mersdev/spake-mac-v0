package com.xdman.spake_mac_v0.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record DeviceVerifyCommandRequest(
  @JsonProperty("message")
  String spake2PlusVerifyCommand
) {
}
