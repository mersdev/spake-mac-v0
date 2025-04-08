package com.xdman.spake_mac_v0.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record VehicleRequestCommandResponse(
  @JsonProperty("message")
  String spake2PlusRequestCommand
) {
}
