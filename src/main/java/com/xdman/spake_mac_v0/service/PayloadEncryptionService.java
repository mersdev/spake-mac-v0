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
public class PayloadEncryptionService {
    private static final byte[] ZERO_IV = new byte[16];
    private static final byte INITIAL_COUNTER = 0x01;
    private static final int MAC_LENGTH = 8;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encrypts payload and generates MAC according to GPC_SPE_014 specification
     *
     * @param payload Plain text data to encrypt
     * @param Kenc   Encryption key
     * @param Kmac   MAC key
     * @param counter Command counter (1-255)
     * @param previousMacChaining MAC chaining value from previous command or null for first command
     * @return SecurePayload containing encrypted data and MAC
     */
    public SecurePayload encryptPayload(byte[] payload, byte[] Kenc, byte[] Kmac, byte counter, byte[] previousMacChaining)
	  throws NoSuchAlgorithmException, javax.crypto.NoSuchPaddingException, java.security.InvalidKeyException, javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException, java.security.InvalidAlgorithmParameterException, NoSuchProviderException {
        // Validate inputs
        if (counter < 1) {
            throw new IllegalArgumentException("Counter must be between 1 and 255");
        }
        if (Kenc == null || Kenc.length != 16) {
            throw new IllegalArgumentException("Kenc must be 16 bytes");
        }
        if (Kmac == null || Kmac.length != 16) {
            throw new IllegalArgumentException("Kmac must be 16 bytes");
        }

        try {

            // Create counter block for AES encryption
            byte[] counterBlock = Arrays.copyOf(ZERO_IV, 16);
            counterBlock[15] = counter;

            // Encrypt payload using AES-CBC with counter block as IV
            SecretKeySpec encKeySpec = new SecretKeySpec(Kenc, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, encKeySpec, new IvParameterSpec(counterBlock));

            // Pad payload if necessary
            byte[] paddedPayload = padPayload(payload);
            byte[] encryptedPayload = cipher.doFinal(paddedPayload);

            // Generate MAC
            byte[] macInput = new byte[previousMacChaining == null ? encryptedPayload.length : previousMacChaining.length + encryptedPayload.length];
            if (previousMacChaining != null) {
                System.arraycopy(previousMacChaining, 0, macInput, 0, previousMacChaining.length);
                System.arraycopy(encryptedPayload, 0, macInput, previousMacChaining.length, encryptedPayload.length);
            } else {
                System.arraycopy(encryptedPayload, 0, macInput, 0, encryptedPayload.length);
            }

            Mac mac = Mac.getInstance("AESCMAC", "BC");
            SecretKeySpec macKeySpec = new SecretKeySpec(Kmac, "AES");
            mac.init(macKeySpec);
            byte[] fullMac = mac.doFinal(macInput);

            // Create response
            SecurePayload securePayload = new SecurePayload();
            securePayload.setEncryptedPayload(encryptedPayload);
            securePayload.setMac(Arrays.copyOf(fullMac, MAC_LENGTH)); // Use first 8 bytes as MAC
            securePayload.setMacChainingValue(fullMac); // Store full MAC as chaining value
            securePayload.setCounter(counter);

            return securePayload;

        } catch (Exception e) {
            log.error("Error encrypting payload", e);
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