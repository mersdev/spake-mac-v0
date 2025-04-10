package com.xdman.spake_mac_v0.model.tlv;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyResponseTlv;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Spake2PlusVerifyResponseTlvTest {

    private static final String VERIFY_RESPONSE_TLV = "5810B169C1D2F8858E659474D2F8858E65949000";

    private Spake2PlusVerifyResponseTlv tlv;

    @BeforeEach
    void setUp() {
        tlv = new Spake2PlusVerifyResponseTlv();
    }

    @Test
    void decode_ValidTlvString_Success() {
        // Act
        Spake2PlusVerifyResponseTlv result = tlv.decode(VERIFY_RESPONSE_TLV);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getDeviceEvidence());
        assertEquals(16, result.getDeviceEvidence().length);
    }

    @Test
    void encode_ValidFields_Success() {
        // Arrange
        tlv.setDeviceEvidence(HexUtil.parseHex("B169C1D2F8858E659474D2F8858E6594"));

        // Act
        String result = tlv.encode();

        // Assert
        assertEquals(VERIFY_RESPONSE_TLV, result);
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

    @Test
    void getFormattedDeviceEvidence_ValidEvidence_ReturnsHexString() {
        // Arrange
        byte[] evidence = HexUtil.parseHex("0B169C1D2F8858E659474D2F8858E65947");
        tlv.setDeviceEvidence(evidence);

        // Act
        String result = HexUtil.toHexString(tlv.getDeviceEvidence());

        // Assert
        assertEquals("0B169C1D2F8858E659474D2F8858E65947", result);
    }
}