package com.xdman.spake_mac_v0.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record VehicleVerifyCommandResponse(
  @JsonProperty("message")
  String spake2PlusVerifyCommand
) {
}
