package com.xdman.spake_mac_v0.model.tlv;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusRequestResponseTlv;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Spake2PlusRequestResponseTlvTest {

    private static final String REQUEST_RESPONSE_TLV = "504104F6C30CA94ED2B6C25A979458BE967458353AA08898C7E763846ED2DFC50F2D58BC76F296DB1743C648ED1207404F925E80F366FB6FF75253502FC6F5C64BF71D9000";

    private Spake2PlusRequestResponseTlv tlv;

    @BeforeEach
    void setUp() {
        tlv = new Spake2PlusRequestResponseTlv();
    }

    @Test
    void decode_ValidTlvString_Success() {
        // Act
        Spake2PlusRequestResponseTlv result = tlv.decode(REQUEST_RESPONSE_TLV);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getCurvePointX());
        assertEquals(65, result.getCurvePointX().length);
        assertEquals(0x04, result.getCurvePointX()[0]); // Verify 0x04 prefix
    }

    @Test
    void encode_ValidFields_Success() {
        byte[] curvePointX = HexUtil.parseHex("04F6C30CA94ED2B6C25A979458BE967458353AA08898C7E763846ED2DFC50F2D58BC76F296DB1743C648ED1207404F925E80F366FB6FF75253502FC6F5C64BF71D");
        byte[] version = HexUtil.parseHex("2FC6");
        BerTlvBuilder builder = new BerTlvBuilder();

        // Add Tag 50h (Curve Point X, 65 bytes)
        builder.addBytes(new BerTag(new byte[]{0x50}), curvePointX);

      // Build TLV data and append status 9000
        byte[] tlvData = builder.buildArray();
        byte[] response = new byte[tlvData.length + 2];
        System.arraycopy(tlvData, 0, response, 0, tlvData.length);
        response[response.length - 2] = (byte) 0x90;
        response[response.length - 1] = (byte) 0x00;

        // Act
        String result = HexUtil.toHexString(response);
        
        // Assert
        assertEquals(REQUEST_RESPONSE_TLV, result);
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
    void encode_InvalidCurvePointLength_ThrowsException() {
        // Arrange
        byte[] invalidCurvePoint = new byte[64]; // Invalid length (should be 65 bytes)
        tlv.setCurvePointX(invalidCurvePoint);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }

    @Test
    void encode_InvalidCurvePointPrefix_ThrowsException() {
        // Arrange
        byte[] invalidCurvePoint = new byte[65];
        invalidCurvePoint[0] = 0x05; // Invalid prefix (should be 0x04)
        tlv.setCurvePointX(invalidCurvePoint);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }
}