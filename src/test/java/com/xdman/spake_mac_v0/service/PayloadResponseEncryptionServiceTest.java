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

class PayloadResponseEncryptionServiceTest extends SpakeMacV0ApplicationTests {
    private static PayloadResponseEncryptionService service;
    private static final byte[] KENC = new byte[16];
    private static final byte[] KRMAC = new byte[16];
    private static final byte RESPONSE_COUNTER_PREFIX = (byte) 0x80;
    
    @BeforeAll
    static void setup() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        service = new PayloadResponseEncryptionService();
        Arrays.fill(KENC, (byte)0x01);
        Arrays.fill(KRMAC, (byte)0x02);
    }
    
    @Test
    void testEncryptResponsePayloadWithValidInputs() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] payload = "Test response payload".getBytes();
        byte counter = 0x01;
        
        SecurePayload result = service.encryptResponsePayload(payload, KENC, KRMAC, counter, null);
        
        assertNotNull(result);
        assertNotNull(result.getEncryptedPayload());
        assertNotNull(result.getMac());
        assertEquals(8, result.getMac().length);
        assertEquals(counter, result.getCounter());
        assertTrue(result.getEncryptedPayload().length > payload.length); // Check padding
    }
    
    @Test
    void testEncryptResponsePayloadWithInvalidCounter() {
        byte[] payload = "Test response payload".getBytes();
        
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptResponsePayload(payload, KENC, KRMAC, (byte)0, null));
    }
    
    @Test
    void testEncryptResponsePayloadWithInvalidKeyLength() {
        byte[] payload = "Test response payload".getBytes();
        byte[] invalidKenc = new byte[15];
        byte[] invalidKrmac = new byte[17];
        
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptResponsePayload(payload, invalidKenc, KRMAC, (byte)1, null));
            
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptResponsePayload(payload, KENC, invalidKrmac, (byte)1, null));
    }
    
    @Test
    void testResponseMacChaining() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] payload1 = "First response payload".getBytes();
        byte[] payload2 = "Second response payload".getBytes();
        
        SecurePayload result1 = service.encryptResponsePayload(payload1, KENC, KRMAC, (byte)1, null);
        SecurePayload result2 = service.encryptResponsePayload(payload2, KENC, KRMAC, (byte)2, result1.getMacChainingValue());
        
        assertNotNull(result2.getMac());
        assertFalse(Arrays.equals(result1.getMac(), result2.getMac()));
        assertNotNull(result2.getMacChainingValue());
    }
    
    @Test
    void testNullPayload() {
        assertThrows(IllegalArgumentException.class, 
            () -> service.encryptResponsePayload(null, KENC, KRMAC, (byte)1, null));
    }
    
    @Test
    void testEmptyPayload() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException {
        byte[] emptyPayload = new byte[0];
        SecurePayload result = service.encryptResponsePayload(emptyPayload, KENC, KRMAC, (byte)1, null);
        
        assertNotNull(result);
        assertTrue(result.getEncryptedPayload().length > 0); // Should contain padding
        assertNotNull(result.getMac());
        assertEquals(8, result.getMac().length);
    }
}