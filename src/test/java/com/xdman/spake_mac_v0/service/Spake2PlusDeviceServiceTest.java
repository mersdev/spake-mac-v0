package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.domain.Spake2PlusDeviceData;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import com.xdman.spake_mac_v0.repository.Spake2PlusDeviceRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class Spake2PlusDeviceServiceTest {
    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";
    private static final String REQUEST_RESPONSE_TLV = "504104F6C30CA94ED2B6C25A979458BE967458353AA08898C7E763846ED2DFC50F2D58BC76F296DB1743C648ED1207404F925E80F366FB6FF75253502FC6F5C64BF71D9000";
    private static final String VERIFY_COMMAND_TLV = "8032000055524104946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF225710CBEC779FF69B8BBED4CBE5FA4A81181B00";

    private Spake2PlusDeviceService spake2PlusDeviceService;
    @Mock
    private Spake2PlusDeviceRepo spake2PlusDeviceRepo;
    private static final String TEST_PASSWORD = "123456";

    @BeforeEach
    void setUp() {
        spake2PlusDeviceService = new Spake2PlusDeviceService(spake2PlusDeviceRepo);
    }

    @Test
    @DisplayName("Process SPAKE2+ Request Successfully")
    void processSpake2PlusRequest_Success() {
        Spake2PlusRequestCommandTlv result = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        Spake2PlusRequestResponseTlv response = spake2PlusDeviceService.processSpake2PlusRequest(result, TEST_PASSWORD, "1234");

        assertNotNull(response);
        assertNotNull(response.getCurvePointX());
        assertEquals(65, response.getCurvePointX().length);
        assertEquals(0x04, response.getCurvePointX()[0]);
    }
}