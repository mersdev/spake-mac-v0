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

class PayloadDecryptionServiceTest extends SpakeMacV0ApplicationTests {
    private static PayloadEncryptionService encryptionService;
    private static PayloadDecryptionService decryptionService;
    private static final byte[] KENC = new byte[16];
    private static final byte[] KMAC = new byte[16];
    
    @BeforeAll
    static void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        encryptionService = new PayloadEncryptionService();
        decryptionService = new PayloadDecryptionService();
        Arrays.fill(KENC, (byte)0x01);
        Arrays.fill(KMAC, (byte)0x02);
    }
    
    @Test
    void testEncryptDecryptCycle() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // Original payload
        byte[] originalPayload = "Test payload for encryption and decryption".getBytes();
        byte counter = 0x01;
        
        // Encrypt the payload
        SecurePayload encryptedResult = encryptionService.encryptPayload(
                originalPayload, KENC, KMAC, counter, null);
        
        // Decrypt the payload
        byte[] decryptedPayload = decryptionService.decryptPayload(
                encryptedResult, KENC, KMAC, null);
        
        // Verify the decrypted payload matches the original
        assertArrayEquals(originalPayload, decryptedPayload);
    }
    
    @Test
    void testMacChaining() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // First command
        byte[] payload1 = "First payload".getBytes();
        SecurePayload result1 = encryptionService.encryptPayload(
                payload1, KENC, KMAC, (byte)1, null);
        
        // Decrypt first command
        byte[] decrypted1 = decryptionService.decryptPayload(
                result1, KENC, KMAC, null);
        assertArrayEquals(payload1, decrypted1);
        
        // Second command with MAC chaining
        byte[] payload2 = "Second payload".getBytes();
        SecurePayload result2 = encryptionService.encryptPayload(
                payload2, KENC, KMAC, (byte)2, result1.getMacChainingValue());
        
        // Decrypt second command with MAC chaining
        byte[] decrypted2 = decryptionService.decryptPayload(
                result2, KENC, KMAC, result1.getMacChainingValue());
        assertArrayEquals(payload2, decrypted2);
    }
    
    @Test
    void testInvalidMac() throws InvalidAlgorithmParameterException, NoSuchPaddingException, 
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, 
            InvalidKeyException, NoSuchProviderException {
        // Encrypt payload
        byte[] payload = "Test payload".getBytes();
        SecurePayload encryptedResult = encryptionService.encryptPayload(
                payload, KENC, KMAC, (byte)1, null);
        
        // Tamper with the MAC
        byte[] originalMac = encryptedResult.getMac();
        byte[] tamperedMac = Arrays.copyOf(originalMac, originalMac.length);
        tamperedMac[0] = (byte)(tamperedMac[0] ^ 0xFF); // Flip bits in first byte
        encryptedResult.setMac(tamperedMac);
        
        // Decryption should fail with SecurityException
        assertThrows(SecurityException.class, () -> 
                decryptionService.decryptPayload(encryptedResult, KENC, KMAC, null));
    }
    
    @Test
    void testInvalidInputs() {
        // Test with null SecurePayload
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptPayload(null, KENC, KMAC, null));
        
        // Test with invalid counter
        SecurePayload invalidCounter = new SecurePayload();
        invalidCounter.setEncryptedPayload(new byte[16]);
        invalidCounter.setMac(new byte[8]);
        invalidCounter.setCounter((byte)0); // Invalid counter
        
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptPayload(invalidCounter, KENC, KMAC, null));
        
        // Test with invalid key lengths
        SecurePayload validPayload = new SecurePayload();
        validPayload.setEncryptedPayload(new byte[16]);
        validPayload.setMac(new byte[8]);
        validPayload.setCounter((byte)1);
        
        byte[] invalidKenc = new byte[15];
        byte[] invalidKmac = new byte[17];
        
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptPayload(validPayload, invalidKenc, KMAC, null));
                
        assertThrows(IllegalArgumentException.class, () -> 
                decryptionService.decryptPayload(validPayload, KENC, invalidKmac, null));
    }
}