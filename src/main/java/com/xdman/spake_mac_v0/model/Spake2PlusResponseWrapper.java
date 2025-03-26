package com.xdman.spake_mac_v0.model;

import com.xdman.spake_mac_v0.domain.Spake2PlusDeviceData;
import com.xdman.spake_mac_v0.domain.Spake2PlusVehicleData;

public record Spake2PlusResponseWrapper(
  Spake2PlusRequestResponseTlv request,
  Spake2PlusDeviceData data
) {
}
