package com.xdman.spake_mac_v0.service;

import com.xdman.spake_mac_v0.SpakeMacV0ApplicationTests;
import com.xdman.spake_mac_v0.model.SecurePayload;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PayloadResponseEncryptDecryptIntegrationTest extends SpakeMacV0ApplicationTests {
    private static PayloadResponseEncryptionService encryptionService;
    private static PayloadResponseDecryptionService decryptionService;
    private static final byte[] KENC = new byte[16];
    private static final byte[] KRMAC = new byte[16];
    
    @BeforeAll
    static void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        encryptionService = new PayloadResponseEncryptionService();
        decryptionService = new PayloadResponseDecryptionService();
        Arrays.fill(KENC, (byte)0x01);
        Arrays.fill(KRMAC, (byte)0x02);
    }
    
    @Test
    void testEncryptDecryptWithTextData() throws InvalidAlgorithmParameterException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException,
            InvalidKeyException, NoSuchProviderException {
        // Test with various text data
        String[] testData = {
            "Hello, World!",
            "Special characters: !@#$%^&*()",
            "Unicode characters: 你好世界",
            "Long text: " + "A".repeat(1000),
            ""
        };
        
        for (int i = 0; i < testData.length; i++) {
            byte[] originalPayload = testData[i].getBytes(StandardCharsets.UTF_8);
            byte counter = (byte)(i + 1);
            
            SecurePayload encrypted = encryptionService.encryptResponsePayload(
                    originalPayload, KENC, KRMAC, counter, null);
            byte[] decrypted = decryptionService.decryptResponsePayload(
                    encrypted, KENC, KRMAC, null);
            
            assertEquals(testData[i], new String(decrypted, StandardCharsets.UTF_8));
        }
    }
    
    @Test
    void testEncryptDecryptWithBinaryData() throws InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Test with binary data
        byte[][] testData = {
            {0x00, 0x01, 0x02, 0x03},
            {(byte)0xFF, (byte)0xFE, (byte)0xFD, (byte)0xFC},
            new byte[16], // All zeros
            new byte[32]  // Larger block
        };
        
        for (int i = 0; i < testData.length; i++) {
            byte counter = (byte)(i + 1);
            SecurePayload encrypted = encryptionService.encryptResponsePayload(
                    testData[i], KENC, KRMAC, counter, null);
            byte[] decrypted = decryptionService.decryptResponsePayload(
                    encrypted, KENC, KRMAC, null);
            
            assertArrayEquals(testData[i], decrypted);
        }
    }
    
    @Test
    void testEncryptDecryptWithMacChaining() throws InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Test MAC chaining with multiple messages
        byte[][] messages = {
            "First response".getBytes(),
            "Second response".getBytes(),
            "Third response".getBytes()
        };
        
        SecurePayload previousResult = null;
        for (int i = 0; i < messages.length; i++) {
            byte counter = (byte)(i + 1);
            byte[] macChaining = previousResult != null ? previousResult.getMacChainingValue() : null;
            
            SecurePayload encrypted = encryptionService.encryptResponsePayload(
                    messages[i], KENC, KRMAC, counter, macChaining);
            byte[] decrypted = decryptionService.decryptResponsePayload(
                    encrypted, KENC, KRMAC, macChaining);
            
            assertArrayEquals(messages[i], decrypted);
            previousResult = encrypted;
        }
    }
    
    @Test
    void testEncryptDecryptWithBlockSizeEdgeCases() throws InvalidAlgorithmParameterException,
            NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, NoSuchProviderException {
        // Test with payloads of various sizes around AES block size
        int[] testSizes = {15, 16, 17, 31, 32, 33};
        
        for (int i = 0; i < testSizes.length; i++) {
            byte[] originalPayload = new byte[testSizes[i]];
            Arrays.fill(originalPayload, (byte)0xAA);
            byte counter = (byte)(i + 1);
            
            SecurePayload encrypted = encryptionService.encryptResponsePayload(
                    originalPayload, KENC, KRMAC, counter, null);
            byte[] decrypted = decryptionService.decryptResponsePayload(
                    encrypted, KENC, KRMAC, null);
            
            assertArrayEquals(originalPayload, decrypted);
        }
    }
}