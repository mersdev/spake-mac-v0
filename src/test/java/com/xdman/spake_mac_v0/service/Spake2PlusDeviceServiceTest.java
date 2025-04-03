package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.SpakeMacV0ApplicationTests;
import com.xdman.spake_mac_v0.domain.Spake2PlusDeviceData;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusResponseWrapper;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyResponseTlv;
import com.xdman.spake_mac_v0.repository.Spake2PlusDeviceRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class Spake2PlusDeviceServiceTest extends SpakeMacV0ApplicationTests {
    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";
    private static final String VERIFY_COMMAND_TLV = "80320000555241045555A715DFA707AB7C04C0F30CA36CAF25C18439C8396FD5234387DC0082C0D0983F91B81796DD0D3EF683B1538934C8BAE5686010186D7645BCDFD6D6B2821657107846D9709130FB6C57569AF87C534BCF00";
    private static final String TEST_PASSWORD = "123456";
    private static final String TEST_REQUEST_ID = "1234";

    @Autowired
    private Spake2PlusDeviceService spake2PlusDeviceService;

    @MockitoBean
    private Spake2PlusDeviceRepo spake2PlusDeviceRepo;

    private Spake2PlusDeviceData mockDeviceData;

    @BeforeEach
    void setUp() {
        mockDeviceData = new Spake2PlusDeviceData();
        mockDeviceData.setW0(new BigInteger("15798853669394257390133159064087829428429240420737596850475606515948308353658"));
        mockDeviceData.setW1(new BigInteger("55620719460622811220416019163427495713352413659338601782359988786191306296648"));
        mockDeviceData.setX(new BigInteger("65094189467859195762383014505031279549878704230834209729570291865454794304043"));
        mockDeviceData.setPassword(TEST_PASSWORD);
        mockDeviceData.setRequestId(TEST_REQUEST_ID);

        when(spake2PlusDeviceRepo.save(any())).thenReturn(mockDeviceData);
        when(spake2PlusDeviceRepo.findByRequestId(TEST_REQUEST_ID)).thenReturn(mockDeviceData);
    }

    @Test
    @DisplayName("Process SPAKE2+ Request Successfully")
    void processSpake2PlusRequest_Success() {
        Spake2PlusRequestCommandTlv request = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        Spake2PlusResponseWrapper wrapper = spake2PlusDeviceService.processSpake2PlusRequest(request, TEST_PASSWORD, TEST_REQUEST_ID);
        Spake2PlusRequestResponseTlv response = wrapper.request();

        assertNotNull(response);
        assertNotNull(response.getCurvePointX());
        assertEquals(65, response.getCurvePointX().length);
        assertEquals(0x04, response.getCurvePointX()[0]);
        assertArrayEquals(new byte[]{0x01, 0x00}, response.getSelectedVodFwVersion());
    }

    @Test
    @DisplayName("Process SPAKE2+ Verify Request Successfully")
    void processSpake2PlusVerifyRequest_Success() {
        Spake2PlusVerifyCommandTlv verifyCommandTlv = new Spake2PlusVerifyCommandTlv().decode(VERIFY_COMMAND_TLV);
        Spake2PlusVerifyResponseTlv response = spake2PlusDeviceService.processSpake2PlusVerifyRequest(verifyCommandTlv, mockDeviceData);

        assertNotNull(response);
        assertNotNull(response.getDeviceEvidence());
        assertEquals(16, response.getDeviceEvidence().length);
    }

//    @Test
//    @DisplayName("Process SPAKE2+ Verify Request with Invalid Vehicle Evidence")
//    void processSpake2PlusVerifyRequest_InvalidEvidence() {
//        Spake2PlusRequestCommandTlv request = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
//        Spake2PlusResponseWrapper wrapper = spake2PlusDeviceService.processSpake2PlusRequest(request, TEST_PASSWORD, TEST_REQUEST_ID);
//        Spake2PlusVerifyCommandTlv verifyCommandTlv = new Spake2PlusVerifyCommandTlv().decode(VERIFY_COMMAND_TLV);
//        verifyCommandTlv.setVehicleEvidence(new byte[16]); // Invalid evidence
//
//        assertThrows(SecurityException.class, () ->
//            spake2PlusDeviceService.processSpake2PlusVerifyRequest(verifyCommandTlv, wrapper.data())
//        );
//    }

    @Test
    @DisplayName("Process SPAKE2+ Request with Invalid Parameters")
    void processSpake2PlusRequest_InvalidParams() {
        Spake2PlusRequestCommandTlv request = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        request.setScryptCost(0); // Invalid Scrypt cost

        assertThrows(IllegalArgumentException.class, () ->
            spake2PlusDeviceService.processSpake2PlusRequest(request, TEST_PASSWORD, TEST_REQUEST_ID)
        );
    }
}