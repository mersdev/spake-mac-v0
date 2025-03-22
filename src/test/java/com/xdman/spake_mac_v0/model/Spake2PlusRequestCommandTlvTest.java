package com.xdman.spake_mac_v0.model;

import com.payneteasy.tlv.HexUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Spake2PlusRequestCommandTlvTest {

    private static final String REQUEST_COMMAND_TLV = "803000002F5B0201005C0201007F5020C010D96A3B251CAD2B49962B7E096EE8656AC10400001000C2020008C3020001D602000300";

    private Spake2PlusRequestCommandTlv tlv;

    @BeforeEach
    void setUp() {
        tlv = new Spake2PlusRequestCommandTlv();
    }

    @Test
    void decode_ValidTlvString_Success() {

         // Act
         Spake2PlusRequestCommandTlv result = new Spake2PlusRequestCommandTlv().decode(REQUEST_COMMAND_TLV);
        // Assert
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
    void encode_ValidFields_Success() {
        // Arrange
        tlv.setVodFwVersions(new byte[]{0x01, 0x00});
        tlv.setDkProtocolVersions(new byte[]{0x01, 0x00});
        tlv.setCryptographicSalt("D96A3B251CAD2B49962B7E096EE8656A");
        tlv.setScryptCost(4096);
        tlv.setBlockSize(8);
        tlv.setParallelization(1);
        tlv.setVehicleBrand("0003");

        // Act
        String result = tlv.encode();

        // Assert
        assertEquals(REQUEST_COMMAND_TLV, result);
    }

    @Test
    void decode_InvalidTlvString_ThrowsException() {
        // Arrange
        String invalidTlv = "invalid_tlv_string";

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.decode(invalidTlv));
    }

    @Test
    void encode_MissingMandatoryFields_ThrowsException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }
}