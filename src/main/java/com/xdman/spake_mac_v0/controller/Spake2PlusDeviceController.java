package com.xdman.spake_mac_v0.controller;

import com.xdman.spake_mac_v0.model.DeviceRequestCommandRequest;
import com.xdman.spake_mac_v0.model.DeviceRequestCommandResponse;
import com.xdman.spake_mac_v0.model.DeviceVerifyCommandRequest;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusResponseWrapper;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.service.Spake2PlusDeviceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Logger;

@Slf4j
@RestController
@RequestMapping("/api/spake2plus/device")
public class Spake2PlusDeviceController {

    @Autowired
    private Spake2PlusDeviceService spake2PlusDeviceService;

    @PostMapping("/request")
    public ResponseEntity<DeviceRequestCommandResponse> processRequest(
        @RequestBody DeviceRequestCommandRequest request) {
        Spake2PlusRequestCommandTlv tlv = new Spake2PlusRequestCommandTlv().decode(request.spake2PlusRequestCommand());
        Spake2PlusResponseWrapper wrapper = spake2PlusDeviceService.processSpake2PlusRequest(tlv, request.password());
        String response = wrapper.request().encode();
        return ResponseEntity.ok(new DeviceRequestCommandResponse(response));
    }

    @PostMapping("/verify")
    public ResponseEntity<DeviceRequestCommandResponse> processVerifyRequest(
            @RequestBody DeviceVerifyCommandRequest request) {
        Spake2PlusVerifyCommandTlv tlv = new Spake2PlusVerifyCommandTlv().decode(request.spake2PlusVerifyCommand());
        Spake2PlusVerifyResponseTlv response = spake2PlusDeviceService.processSpake2PlusVerifyRequest(tlv);
        return ResponseEntity.ok(new DeviceRequestCommandResponse(response.encode()));
    }
}
