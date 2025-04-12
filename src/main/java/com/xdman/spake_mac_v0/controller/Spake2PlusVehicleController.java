package com.xdman.spake_mac_v0.controller;

import com.xdman.spake_mac_v0.model.DeviceRequestCommandRequest;
import com.xdman.spake_mac_v0.model.DeviceRequestCommandResponse;
import com.xdman.spake_mac_v0.model.DeviceVerifyCommandRequest;
import com.xdman.spake_mac_v0.model.DeviceVerifyCommandResponse;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusResponseWrapper;
import com.xdman.spake_mac_v0.model.VehicleRequestCommandRequest;
import com.xdman.spake_mac_v0.model.VehicleRequestCommandResponse;
import com.xdman.spake_mac_v0.model.VehicleVerifyCommandRequest;
import com.xdman.spake_mac_v0.model.VehicleVerifyCommandResponse;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.service.Spake2PlusDeviceService;
import com.xdman.spake_mac_v0.service.Spake2PlusVehicleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/spake2plus/vehicle")
public class Spake2PlusVehicleController {

    @Autowired
    private Spake2PlusVehicleService spake2PlusVehicleService;

    @PostMapping("/request")
    public ResponseEntity<VehicleRequestCommandResponse> processRequest(
        @RequestBody VehicleRequestCommandRequest request) {
        Spake2PlusRequestWrapper wrapper = spake2PlusVehicleService.generateSpake2PlusRequest(
          request.password(),
          request.salt()
        );
        String tlv = wrapper.response().encode();
        return ResponseEntity.ok(new VehicleRequestCommandResponse(tlv));
    }

    @PostMapping("/verify")
    public ResponseEntity<VehicleVerifyCommandResponse> processVerifyRequest(
      @RequestBody VehicleVerifyCommandRequest request) {
        Spake2PlusRequestResponseTlv tlv = new Spake2PlusRequestResponseTlv().decode(request.spake2PlusRequestResponse());
        Spake2PlusVerifyCommandTlv response = spake2PlusVehicleService.createSpake2PlusVerifyRequest(tlv);
        return ResponseEntity.ok(new VehicleVerifyCommandResponse(response.encode()));
    }
}
