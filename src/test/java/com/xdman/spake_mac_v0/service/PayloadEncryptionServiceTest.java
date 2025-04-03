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

class PayloadEncryptionServiceTest extends SpakeMacV0ApplicationTests {
    private static PayloadEncryptionService service;
    private static final byte[] KENC = new byte[16];
    private static final byte[] KMAC = new byte[16];
    
    @BeforeAll
    static void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        service = new PayloadEncryptionService();
        Arrays.fill(KENC, (byte)0x01);
        Arrays.fill(KMAC, (byte)0x02);
    }
    
    @Test
    void testEncryptPayloadWithValidInputs() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] payload = "Test payload".getBytes();
        byte counter = 0x01;
        
        SecurePayload result = service.encryptPayload(payload, KENC, KMAC, counter, null);
        
        assertNotNull(result);
        assertNotNull(result.getEncryptedPayload());
        assertNotNull(result.getMac());
        assertEquals(8, result.getMac().length);
        assertEquals(counter, result.getCounter());
    }
    
    @Test
    void testEncryptPayloadWithInvalidCounter() {
        byte[] payload = "Test payload".getBytes();
        
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptPayload(payload, KENC, KMAC, (byte)0, null));
        
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptPayload(payload, KENC, KMAC, (byte)256, null));
    }
    
    @Test
    void testEncryptPayloadWithInvalidKeyLength() {
        byte[] payload = "Test payload".getBytes();
        byte[] invalidKenc = new byte[15];
        byte[] invalidKmac = new byte[17];
        
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptPayload(payload, invalidKenc, KMAC, (byte)1, null));
            
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptPayload(payload, KENC, invalidKmac, (byte)1, null));
    }
    
    @Test
    void testMacChaining() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] payload1 = "First payload".getBytes();
        byte[] payload2 = "Second payload".getBytes();
        
        SecurePayload result1 = service.encryptPayload(payload1, KENC, KMAC, (byte)1, null);
        SecurePayload result2 = service.encryptPayload(payload2, KENC, KMAC, (byte)2, result1.getMacChainingValue());
        
        assertNotNull(result2.getMac());
        assertFalse(Arrays.equals(result1.getMac(), result2.getMac()));
    }
}