package com.xdman.spake_mac_v0.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record DeviceRequestCommandRequest(
  @JsonProperty("message")
  String spake2PlusRequestCommand,
  @JsonProperty("password")
  String password
) {
}
