package com.xdman.spake_mac_v0.model;

public record VehicleRequestCommandRequest(
  String password,
  String salt
) {
}
