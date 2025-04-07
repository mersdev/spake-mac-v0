package com.xdman.spake_mac_v0.model;

import com.xdman.spake_mac_v0.domain.Spake2PlusVehicleData;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestCommandTlv;

public record Spake2PlusRequestWrapper(
  Spake2PlusRequestCommandTlv response,
  Spake2PlusVehicleData data
) {
}
