package com.xdman.spake_mac_v0.model.tlv;

import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.SecurePayload;
import com.xdman.spake_mac_v0.service.PayloadResponseDecryptionService;
import com.xdman.spake_mac_v0.service.PayloadResponseEncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

class WriteCompletionOfDigitalKeyDataSendingTest {

    @Mock
    private PayloadResponseEncryptionService encryptionService;

    @Mock
    private PayloadResponseDecryptionService decryptionService;

    @InjectMocks
    private WriteCompletionOfDigitalKeyDataSending tlv;

    private static final byte[] TEST_KENC = HexUtil.parseHex("0123456789ABCDEF0123456789ABCDEF");
    private static final byte[] TEST_KRMAC = HexUtil.parseHex("FEDCBA9876543210FEDCBA9876543210");
    private static final byte[] TEST_MAC_CHAINING = HexUtil.parseHex("0000000000000000");
    private static final String ENCRYPTED_PAYLOAD = "AABBCCDD";
    private static final byte[] DECRYPTED_DATA = new byte[]{0x55, 0x00, (byte) 0x90, 0x00};

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        tlv.setKenc(TEST_KENC);
        tlv.setKrmac(TEST_KRMAC);
        tlv.setPreviousMacChaining(TEST_MAC_CHAINING);
        tlv.setCounter((byte) 1);
    }

    @Test
    void decode_ValidEncryptedPayload_Success() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Arrange
        when(decryptionService.decryptResponsePayload(
            any(SecurePayload.class),
            eq(TEST_KENC),
            eq(TEST_KRMAC),
            eq(TEST_MAC_CHAINING)
        )).thenReturn(DECRYPTED_DATA);

        // Act
        WriteCompletionOfDigitalKeyDataSending result = (WriteCompletionOfDigitalKeyDataSending) tlv.decode(ENCRYPTED_PAYLOAD);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.getCounter());
        assertArrayEquals(TEST_MAC_CHAINING, result.getPreviousMacChaining());
    }

    @Test
    void decode_NullTlvString_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> tlv.decode(null));
    }

    @Test
    void decode_EmptyTlvString_ThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> tlv.decode(""));
    }

    @Test
    void decode_InvalidDecryptedFormat_ThrowsException() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Arrange
        when(decryptionService.decryptResponsePayload(
            any(SecurePayload.class),
            eq(TEST_KENC),
            eq(TEST_KRMAC),
            eq(TEST_MAC_CHAINING)
        )).thenReturn(new byte[]{0x00, 0x00}); // Invalid format

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.decode(ENCRYPTED_PAYLOAD));
    }

    @Test
    void encode_ValidData_Success() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Arrange
        byte[] newMacChaining = HexUtil.parseHex("1111111111111111");
        SecurePayload mockPayload = new SecurePayload();
        mockPayload.setEncryptedPayload(HexUtil.parseHex(ENCRYPTED_PAYLOAD));
        mockPayload.setMacChainingValue(newMacChaining);

        when(encryptionService.encryptResponsePayload(
            any(byte[].class),
            eq(TEST_KENC),
            eq(TEST_KRMAC),
            eq((byte) 1),
            eq(TEST_MAC_CHAINING)
        )).thenReturn(mockPayload);

        // Act
        String result = tlv.encode();

        // Assert
        assertEquals(ENCRYPTED_PAYLOAD, result);
        assertEquals(2, tlv.getCounter()); // Counter should be incremented
        assertArrayEquals(newMacChaining, tlv.getPreviousMacChaining());
    }

    @Test
    void encode_EncryptionFails_ThrowsException() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Arrange
        when(encryptionService.encryptResponsePayload(
            any(byte[].class),
            eq(TEST_KENC),
            eq(TEST_KRMAC),
            eq((byte) 1),
            eq(TEST_MAC_CHAINING)
        )).thenThrow(new IllegalArgumentException("Encryption failed"));

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> tlv.encode());
    }
}