package com.xdman.spake_mac_v0.service;

import com.xdman.spake_mac_v0.SpakeMacV0ApplicationTests;
import com.xdman.spake_mac_v0.model.SecurePayload;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PayloadResponseDecryptionServiceTest extends SpakeMacV0ApplicationTests {
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
    void testEncryptDecryptCycle() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // Original payload
        byte[] originalPayload = "Test response payload for encryption and decryption".getBytes();
        byte counter = 0x01;
        
        // Encrypt the payload
        SecurePayload encryptedResult = encryptionService.encryptResponsePayload(
                originalPayload, KENC, KRMAC, counter, null);
        
        // Decrypt the payload
        byte[] decryptedPayload = decryptionService.decryptResponsePayload(
                encryptedResult, KENC, KRMAC, null);
        
        // Verify the decrypted payload matches the original
        assertArrayEquals(originalPayload, decryptedPayload);
    }
    
    @Test
    void testMacChaining() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // First response
        byte[] payload1 = "First response payload".getBytes();
        SecurePayload result1 = encryptionService.encryptResponsePayload(
                payload1, KENC, KRMAC, (byte)1, null);
        
        // Decrypt first response
        byte[] decrypted1 = decryptionService.decryptResponsePayload(
                result1, KENC, KRMAC, null);
        assertArrayEquals(payload1, decrypted1);
        
        // Second response with MAC chaining
        byte[] payload2 = "Second response payload".getBytes();
        SecurePayload result2 = encryptionService.encryptResponsePayload(
                payload2, KENC, KRMAC, (byte)2, result1.getMacChainingValue());
        
        // Decrypt second response with MAC chaining
        byte[] decrypted2 = decryptionService.decryptResponsePayload(
                result2, KENC, KRMAC, result1.getMacChainingValue());
        assertArrayEquals(payload2, decrypted2);
    }
    
    @Test
    void testInvalidMac() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // Encrypt payload
        byte[] payload = "Test response payload".getBytes();
        SecurePayload encryptedResult = encryptionService.encryptResponsePayload(
                payload, KENC, KRMAC, (byte)1, null);
        
        // Tamper with the MAC
        byte[] originalMac = encryptedResult.getMac();
        byte[] tamperedMac = Arrays.copyOf(originalMac, originalMac.length);
        tamperedMac[0] = (byte)(tamperedMac[0] ^ 0xFF); // Flip bits in first byte
        encryptedResult.setMac(tamperedMac);
        
        // Decryption should fail with SecurityException
        assertThrows(SecurityException.class, () -> 
                decryptionService.decryptResponsePayload(encryptedResult, KENC, KRMAC, null));
    }
    
    @Test
    void testInvalidInputs() {
        // Test with null SecurePayload
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptResponsePayload(null, KENC, KRMAC, null));
        
        // Test with invalid counter
        SecurePayload invalidCounter = new SecurePayload();
        invalidCounter.setEncryptedPayload(new byte[16]);
        invalidCounter.setMac(new byte[8]);
        invalidCounter.setCounter((byte)0); // Invalid counter
        
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptResponsePayload(invalidCounter, KENC, KRMAC, null));
        
        // Test with invalid key lengths
        SecurePayload validPayload = new SecurePayload();
        validPayload.setEncryptedPayload(new byte[16]);
        validPayload.setMac(new byte[8]);
        validPayload.setCounter((byte)1);
        
        byte[] invalidKenc = new byte[15];
        byte[] invalidKrmac = new byte[17];
        
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptResponsePayload(validPayload, invalidKenc, KRMAC, null));
                
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptResponsePayload(validPayload, KENC, invalidKrmac, null));
    }
}