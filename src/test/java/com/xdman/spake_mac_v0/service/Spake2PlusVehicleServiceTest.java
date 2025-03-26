package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.domain.Spake2PlusVehicleData;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.repository.Spake2PlusVehicleRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest
public class Spake2PlusVehicleServiceTest {
    private static final String TEST_PASSWORD = "123456";
    private static final String TEST_SALT = "A5A5A5A5";
    private static final String TEST_REQUEST_ID = "5678";
    private static final String RESPONSE_CURVE_POINT_X = "04570F5E799A1CA6CD41E331FB8342C3C22E5B80AF03BDAF5D0F3E7255BE9CA9F96C5649D3D8D91EAFBF80065D6EE2496D4CD503B6F5AE6DDAA1ABCD7CE9092308";

    @Autowired
    private Spake2PlusVehicleService spake2PlusVehicleService;

    @MockitoBean
    private Spake2PlusVehicleRepo spake2PlusVehicleRepo;

    private Spake2PlusVehicleData mockVehicleData;

    @BeforeEach
    void setUp() {
        mockVehicleData = new Spake2PlusVehicleData();
        mockVehicleData.setW0(new BigInteger("123456789"));
        mockVehicleData.setW1(new BigInteger("987654321"));
        mockVehicleData.setRequestId(TEST_REQUEST_ID);

        when(spake2PlusVehicleRepo.save(any())).thenReturn(mockVehicleData);
        when(spake2PlusVehicleRepo.findByRequestId(TEST_REQUEST_ID)).thenReturn(mockVehicleData);
    }

    @Test
    @DisplayName("Create SPAKE2+ Request Successfully")
    void createSpake2PlusRequest_Success() {
        Spake2PlusRequestWrapper wrapper = spake2PlusVehicleService.createSpake2PlusRequest(
            TEST_PASSWORD, TEST_SALT, TEST_REQUEST_ID
        );
        Spake2PlusRequestCommandTlv request = wrapper.response();

        assertNotNull(request);
        assertEquals(TEST_SALT, request.getCryptographicSalt());
        assertEquals(4096, request.getScryptCost());
        assertEquals(8, request.getBlockSize());
        assertEquals(1, request.getParallelization());
        assertArrayEquals(new byte[]{0x01, 0x00}, request.getVodFwVersions());
        assertArrayEquals(new byte[]{0x01, 0x00}, request.getDkProtocolVersions());
    }

    @Test
    @DisplayName("Process SPAKE2+ Response Successfully")
    void processSpake2PlusResponse_Success() {
        Spake2PlusRequestResponseTlv response = new Spake2PlusRequestResponseTlv();
        response.setCurvePointX(HexUtil.parseHex(RESPONSE_CURVE_POINT_X));
        response.setSelectedVodFwVersion(new byte[]{0x01, 0x00});

        Spake2PlusRequestWrapper wrapper = spake2PlusVehicleService.createSpake2PlusRequest(
          TEST_PASSWORD, TEST_SALT, TEST_REQUEST_ID
        );
        Spake2PlusVerifyCommandTlv verifyCommand = spake2PlusVehicleService.processSpake2PlusResponse(
            response, wrapper.data()
        );

        assertNotNull(verifyCommand);
        assertNotNull(verifyCommand.getCurvePointY());
        assertEquals(65, verifyCommand.getCurvePointY().length);
        assertEquals(0x04, verifyCommand.getCurvePointY()[0]);
        assertNotNull(verifyCommand.getVehicleEvidence());
        assertEquals(16, verifyCommand.getVehicleEvidence().length);
    }

    @Test
    @DisplayName("Process SPAKE2+ Response with Invalid Curve Point")
    void processSpake2PlusResponse_InvalidCurvePoint() {
        Spake2PlusRequestResponseTlv response = new Spake2PlusRequestResponseTlv();
        Spake2PlusRequestWrapper wrapper = spake2PlusVehicleService.createSpake2PlusRequest(
          TEST_PASSWORD, TEST_SALT, TEST_REQUEST_ID
        );
        response.setCurvePointX(new byte[32]); // Invalid curve point

        assertThrows(IllegalArgumentException.class, () ->
            spake2PlusVehicleService.processSpake2PlusResponse(response, wrapper.data())
        );
    }
}
