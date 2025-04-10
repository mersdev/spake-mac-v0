package com.xdman.spake_mac_v0.model.tlv;
import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.tlv.Spake2PlusVerifyCommandTlv;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Spake2PlusVerifyCommandTlvTest {

    private static final String VERIFY_COMMAND_TLV = "8032000055524104946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF225710CBEC779FF69B8BBED4CBE5FA4A81181B00";

    private Spake2PlusVerifyCommandTlv tlv;

    @BeforeEach
    void setUp() {
        tlv = new Spake2PlusVerifyCommandTlv();
    }

    @Test
    void decode_ValidTlvString_Success() {
        // Act
        Spake2PlusVerifyCommandTlv result = tlv.decode(VERIFY_COMMAND_TLV);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getCurvePointY());
        assertEquals(65, result.getCurvePointY().length);
        assertEquals(0x04, result.getCurvePointY()[0]); // Verify 0x04 prefix
        assertNotNull(result.getVehicleEvidence());
        assertEquals(16, result.getVehicleEvidence().length);
    }

    @Test
    void encode_ValidFields_Success() {
        // Curve point Y (65 bytes)
        byte[] curvePointY = HexUtil.parseHex("04946594D3B6F452733296BD761EBD655C987CD8B49690A5F4FF7F245A1A865E4DFB49112FE5617462939E6CEDC74E1C754B647E45B56F6A5AF347309476C2EF22");
        // Vehicle evidence M[1] (16 bytes) - Corrected last byte to 0x1B [[2]][[7]]
        byte[] m1 = HexUtil.parseHex("CBEC779FF69B8BBED4CBE5FA4A81181B");

        // Arrange
        tlv.setCurvePointY(curvePointY);
        tlv.setVehicleEvidence(m1);
                                           

        // Act
        String result = tlv.encode();

        // Assert
        assertEquals(VERIFY_COMMAND_TLV, result);
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
        tlv.setCurvePointY(invalidCurvePoint);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }

    @Test
    void encode_InvalidVehicleEvidenceLength_ThrowsException() {
        // Arrange
        byte[] invalidEvidence = new byte[15]; // Invalid length (should be 16 bytes)
        tlv.setVehicleEvidence(invalidEvidence);

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }
}