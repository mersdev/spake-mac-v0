package com.xdman.spake_mac_v0.service;

import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusResponseWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.repository.Spake2PlusDeviceRepo;
import com.xdman.spake_mac_v0.repository.Spake2PlusVehicleRepo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest
class Spake2PlusIntegrationTest {

    @Autowired
    private Spake2PlusVehicleService vehicleService;

    @Autowired
    private Spake2PlusDeviceService deviceService;

    @MockitoBean
    private Spake2PlusVehicleRepo vehicleRepo;

    @MockitoBean
    private Spake2PlusDeviceRepo deviceRepo;

    private static final String TEST_PASSWORD = "0102030405060708090A0B0C0D0E0F10";
    private static final String TEST_SALT = "000102030405060708090A0B0C0D0E0F";
    private static final String TEST_REQUEST_ID = "test-request-id";

    private Logger log = Logger.getLogger(Spake2PlusIntegrationTest.class.getName());


    @Test
    @DisplayName("Full SPAKE2+ Protocol Flow Integration Test")
    void testFullSpake2PlusProtocolFlow() {
        // Step 1: Vehicle creates initial request
        Spake2PlusRequestWrapper vehicleWrapper = vehicleService.createSpake2PlusRequest(
            TEST_PASSWORD, TEST_SALT, TEST_REQUEST_ID);
        Spake2PlusRequestCommandTlv initialRequest = vehicleWrapper.response();
        
        assertNotNull(initialRequest, "Initial request should not be null");
        assertEquals(TEST_SALT, initialRequest.getCryptographicSalt(), "Salt should match");
        assertEquals(4096, initialRequest.getScryptCost(), "Scrypt cost should be 4096");
        assertEquals(8, initialRequest.getBlockSize(), "Block size should be 8");
        assertEquals(1, initialRequest.getParallelization(), "Parallelization should be 1");

        // Step 2: Device processes request and generates response
        Spake2PlusResponseWrapper deviceWrapper = deviceService.processSpake2PlusRequest(
            initialRequest, TEST_PASSWORD, TEST_REQUEST_ID);
        Spake2PlusRequestResponseTlv deviceResponse = deviceWrapper.request();

        assertNotNull(deviceResponse, "Device response should not be null");
        assertNotNull(deviceResponse.getCurvePointX(), "Curve point X should not be null");
        assertEquals(65, deviceResponse.getCurvePointX().length, "Curve point X should be 65 bytes");
        assertEquals(0x04, deviceResponse.getCurvePointX()[0], "First byte should be 0x04");

        // Step 3: Vehicle processes device response and creates verify request
        Spake2PlusVerifyCommandTlv verifyRequest = vehicleService.processSpake2PlusResponse(
            deviceResponse, vehicleWrapper.data());

        assertNotNull(verifyRequest, "Verify request should not be null");
        assertNotNull(verifyRequest.getCurvePointY(), "Curve point Y should not be null");
        assertEquals(65, verifyRequest.getCurvePointY().length, "Curve point Y should be 65 bytes");
        assertEquals(0x04, verifyRequest.getCurvePointY()[0], "First byte should be 0x04");
        assertNotNull(verifyRequest.getVehicleEvidence(), "Vehicle evidence should not be null");
        assertEquals(16, verifyRequest.getVehicleEvidence().length, "Vehicle evidence should be 16 bytes");

        // Step 4: Device processes verify request and generates final response
        Spake2PlusVerifyResponseTlv verifyResponse = deviceService.processSpake2PlusVerifyRequest(
            verifyRequest, deviceWrapper.data());

        System.out.println("w0: "+ deviceWrapper.data().getW0());
        System.out.println("w1: "+ deviceWrapper.data().getW1());
        System.out.println("x: "+ deviceWrapper.data().getX());
        System.out.println("Ex" + verifyRequest.encode());
        assertNotNull(verifyResponse, "Verify response should not be null");
        assertNotNull(verifyResponse.getDeviceEvidence(), "Device evidence should not be null");
        assertEquals(16, verifyResponse.getDeviceEvidence().length, "Device evidence should be 16 bytes");
    }
}