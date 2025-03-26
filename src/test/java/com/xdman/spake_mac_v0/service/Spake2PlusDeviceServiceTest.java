package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
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

@SpringBootTest
public class Spake2PlusDeviceServiceTest {
    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";
    private static final String VERIFY_COMMAND_TLV = "8032000055524104946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF225710CBEC779FF69B8BBED4CBE5FA4A81181B00";
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
        mockDeviceData.setW0(new BigInteger("41881797154452915604345648512661226679850134709488290698776722978274406518150"));
        mockDeviceData.setW1(new BigInteger("108151664552462919057744750951001878565271522818407009562454456248830845814725"));
        mockDeviceData.setX(new BigInteger("62527515901273762735066442485805227919656465320777236508385623481531306198857"));
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

//    @Test
//    @DisplayName("Process SPAKE2+ Verify Request Successfully")
//    void processSpake2PlusVerifyRequest_Success() {
//        Spake2PlusRequestCommandTlv request = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
//        Spake2PlusResponseWrapper wrapper = spake2PlusDeviceService.processSpake2PlusRequest(request, TEST_PASSWORD, TEST_REQUEST_ID);
//        Spake2PlusVerifyCommandTlv verifyCommandTlv = new Spake2PlusVerifyCommandTlv().decode(VERIFY_COMMAND_TLV);
//        Spake2PlusVerifyResponseTlv response = spake2PlusDeviceService.processSpake2PlusVerifyRequest(verifyCommandTlv, wrapper.data());
//
//        assertNotNull(response);
//        assertNotNull(response.getDeviceEvidence());
//        assertEquals(16, response.getDeviceEvidence().length);
//    }
//
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