package com.xdman.spake_mac_v0.service;

import com.xdman.spake_mac_v0.model.SecurePayload;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

@Slf4j
@Service
public class PayloadResponseEncryptionService {
    private static final byte[] ZERO_IV = new byte[16];
    private static final int MAC_LENGTH = 8;
    private static final byte RESPONSE_COUNTER_PREFIX = (byte) 0x80;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encrypts response payload and generates MAC according to GPC_SPE_014 section 6.2.7
     *
     * @param payload Plain text response data to encrypt
     * @param Kenc Encryption key
     * @param Krmac Response MAC key
     * @param counter Command counter value (1-255)
     * @param previousMacChaining MAC chaining value from command
     * @return SecurePayload containing encrypted response data and MAC
     */
    public SecurePayload encryptResponsePayload(byte[] payload, byte[] Kenc, byte[] Krmac, byte counter, byte[] previousMacChaining)
            throws NoSuchAlgorithmException, javax.crypto.NoSuchPaddingException, java.security.InvalidKeyException,
            javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException,
            java.security.InvalidAlgorithmParameterException, NoSuchProviderException {
        
        // Validate inputs
        if (payload == null) {
            throw new IllegalArgumentException("Payload must not be null");
        }
        if (counter < 1) {
            throw new IllegalArgumentException("Counter must be between 1 and 255");
        }
        if (Kenc == null || Kenc.length != 16) {
            throw new IllegalArgumentException("Kenc must be 16 bytes");
        }
        if (Krmac == null || Krmac.length != 16) {
            throw new IllegalArgumentException("Krmac must be 16 bytes");
        }

        try {
            // Create response counter block (0x80 || 0x00...00 || counter)
            byte[] counterBlock = Arrays.copyOf(ZERO_IV, 16);
            counterBlock[0] = RESPONSE_COUNTER_PREFIX; // Set 0x80 prefix
            counterBlock[15] = counter;

            // Encrypt payload using AES-CBC with response counter block as IV
            SecretKeySpec encKeySpec = new SecretKeySpec(Kenc, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, new IvParameterSpec(counterBlock));

            // Pad payload if necessary
            byte[] paddedPayload = padPayload(payload);
            byte[] encryptedPayload = cipher.doFinal(paddedPayload);

            // Generate MAC input by concatenating previous MAC chaining value (if present) with encrypted payload
            byte[] macInput = new byte[previousMacChaining == null ? encryptedPayload.length : previousMacChaining.length + encryptedPayload.length];
            if (previousMacChaining != null) {
                System.arraycopy(previousMacChaining, 0, macInput, 0, previousMacChaining.length);
                System.arraycopy(encryptedPayload, 0, macInput, previousMacChaining.length, encryptedPayload.length);
            } else {
                System.arraycopy(encryptedPayload, 0, macInput, 0, encryptedPayload.length);
            }

            // Calculate MAC using CMAC with Krmac
            Mac mac = Mac.getInstance("AESCMAC", "BC");
            SecretKeySpec rmacKeySpec = new SecretKeySpec(Krmac, "AES");
            mac.init(rmacKeySpec);
            byte[] fullMac = mac.doFinal(macInput);

            // Create response
            SecurePayload securePayload = new SecurePayload();
            securePayload.setEncryptedPayload(encryptedPayload);
            securePayload.setMac(Arrays.copyOf(fullMac, MAC_LENGTH)); // Use first 8 bytes as MAC
            securePayload.setMacChainingValue(fullMac); // Store full MAC as chaining value
            securePayload.setCounter(counter);

            return securePayload;

        } catch (Exception e) {
            log.error("Error encrypting response payload", e);
            throw e;
        }
    }

    /**
     * Pads payload to AES block size (16 bytes) using ISO/IEC 9797-1 padding method 2
     */
    private byte[] padPayload(byte[] payload) {
        int paddingLength = 16 - (payload.length % 16);
        byte[] paddedPayload = new byte[payload.length + paddingLength];
        System.arraycopy(payload, 0, paddedPayload, 0, payload.length);
        paddedPayload[payload.length] = (byte) 0x80; // Add padding start marker
        return paddedPayload;
    }
}