package com.xdman.spake_mac_v0.service;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestCommandTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusRequestResponseTlv;
import com.xdman.spake_mac_v0.model.Spake2PlusVerifyCommandTlv;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

public class Spake2PlusServiceTest {
    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";
    private static final String REQUEST_RESPONSE_TLV = "504104F6C30CA94ED2B6C25A979458BE967458353AA08898C7E763846ED2DFC50F2D58BC76F296DB1743C648ED1207404F925E80F366FB6FF75253502FC6F5C64BF71D9000";
    private static final String VERIFY_COMMAND_TLV = "8032000055524104946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF225710CBEC779FF69B8BBED4CBE5FA4A81181B00";

    private Spake2PlusService spake2PlusService;
    private static final String TEST_PASSWORD = "123456";
    private static final String TEST_SALT = "D96A3B251CAD2B49962B7E096EE8656A";

    @BeforeEach
    void setUp() {
        spake2PlusService = new Spake2PlusService();
    }


    @Test
    @DisplayName("Create SPAKE2+ Request Successfully using Salt given")
    void createSpake2PlusRequest_Success() {
        Spake2PlusRequestCommandTlv result = spake2PlusService.createSpake2PlusRequest(TEST_SALT);
        assertNotNull(result);
        assertArrayEquals(new byte[]{0x01, 0x00}, result.getVodFwVersions());
        assertArrayEquals(new byte[]{0x01, 0x00}, result.getDkProtocolVersions());
        assertEquals("D96A3B251CAD2B49962B7E096EE8656A", result.getCryptographicSalt());
        assertEquals(4096, result.getScryptCost());
        assertEquals(8, result.getBlockSize());
        assertEquals(1, result.getParallelization());
        assertEquals("0003", result.getVehicleBrand());

        // Verify combined Scrypt config
        byte[] expectedScryptConfig = new byte[24];
        System.arraycopy(HexUtil.parseHex(result.getCryptographicSalt()), 0, expectedScryptConfig, 0, 16);
        System.arraycopy(ByteBuffer.allocate(4).putInt(result.getScryptCost()).array(), 0, expectedScryptConfig, 16, 4);
        System.arraycopy(ByteBuffer.allocate(2).putShort((short)(result.getBlockSize().intValue())).array(), 0, expectedScryptConfig, 20, 2);
        System.arraycopy(ByteBuffer.allocate(2).putShort((short)result.getParallelization().intValue()).array(), 0, expectedScryptConfig, 22, 2);
        assertArrayEquals(expectedScryptConfig, result.getScryptConfig());
    }

    @Test
    @DisplayName("Process SPAKE2+ Request Successfully")
    void processSpake2PlusRequest_Success() {
        Spake2PlusRequestCommandTlv result = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        Spake2PlusRequestResponseTlv response = spake2PlusService.processSpake2PlusRequest(result, TEST_PASSWORD);
        assertNotNull(response);
        assertNotNull(response.getCurvePointX());
        assertEquals(65, response.getCurvePointX().length);
        assertEquals(0x04, response.getCurvePointX()[0]);
    }

    @Test
    @DisplayName("Process SPAKE2+ Response Successfully")
    void processSpake2PlusResponse_Success() {
        Spake2PlusRequestResponseTlv result = new Spake2PlusRequestResponseTlv().decode(REQUEST_RESPONSE_TLV);
        Spake2PlusVerifyCommandTlv response = spake2PlusService.processSpake2PlusResponse(result);
        assertNotNull(response);
    }





}