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
public class PayloadDecryptionService {
    private static final byte[] ZERO_IV = new byte[16];
    private static final int MAC_LENGTH = 8;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Decrypts payload and verifies MAC according to GPC_SPE_014 specification
     *
     * @param securePayload SecurePayload containing encrypted data and MAC
     * @param Kenc Encryption key
     * @param Kmac MAC key
     * @param previousMacChaining MAC chaining value from previous command or null for first command
     * @return Decrypted payload as byte array
     * @throws Exception If MAC verification fails or decryption fails
     */
    public byte[] decryptPayload(SecurePayload securePayload, byte[] Kenc, byte[] Kmac, byte[] previousMacChaining)
            throws NoSuchAlgorithmException, javax.crypto.NoSuchPaddingException, java.security.InvalidKeyException,
            javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException,
            java.security.InvalidAlgorithmParameterException, NoSuchProviderException {
        
        // Validate inputs
        if (securePayload == null || securePayload.getEncryptedPayload() == null || securePayload.getMac() == null) {
            throw new IllegalArgumentException("SecurePayload and its fields must not be null");
        }
        if (securePayload.getCounter() < 1) {
            throw new IllegalArgumentException("Counter must be between 1 and 255");
        }
        if (Kenc == null || Kenc.length != 16) {
            throw new IllegalArgumentException("Kenc must be 16 bytes");
        }
        if (Kmac == null || Kmac.length != 16) {
            throw new IllegalArgumentException("Kmac must be 16 bytes");
        }

        try {
            // Verify MAC first
            if (!verifyMac(securePayload, Kmac, previousMacChaining)) {
                throw new SecurityException("MAC verification failed");
            }

            // Create counter block for AES decryption
            byte[] counterBlock = Arrays.copyOf(ZERO_IV, 16);
            counterBlock[15] = securePayload.getCounter();

            // Decrypt payload using AES-CBC with counter block as IV
            SecretKeySpec encKeySpec = new SecretKeySpec(Kenc, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, encKeySpec, new IvParameterSpec(counterBlock));

            byte[] paddedDecryptedPayload = cipher.doFinal(securePayload.getEncryptedPayload());
            
            // Remove padding
            return removePadding(paddedDecryptedPayload);

        } catch (Exception e) {
            log.error("Error decrypting payload", e);
            throw e;
        }
    }

    /**
     * Verifies the MAC of the secure payload
     * 
     * @param securePayload SecurePayload containing encrypted data and MAC
     * @param Kmac MAC key
     * @param previousMacChaining MAC chaining value from previous command or null for first command
     * @return true if MAC is valid, false otherwise
     */
    private boolean verifyMac(SecurePayload securePayload, byte[] Kmac, byte[] previousMacChaining) 
            throws NoSuchAlgorithmException, NoSuchProviderException, java.security.InvalidKeyException {
        // Generate MAC input
        byte[] encryptedPayload = securePayload.getEncryptedPayload();
        byte[] macInput = new byte[previousMacChaining == null ? encryptedPayload.length : previousMacChaining.length + encryptedPayload.length];
        
        if (previousMacChaining != null) {
            System.arraycopy(previousMacChaining, 0, macInput, 0, previousMacChaining.length);
            System.arraycopy(encryptedPayload, 0, macInput, previousMacChaining.length, encryptedPayload.length);
        } else {
            System.arraycopy(encryptedPayload, 0, macInput, 0, encryptedPayload.length);
        }

        // Calculate MAC
        Mac mac = Mac.getInstance("AESCMAC", "BC");
        SecretKeySpec macKeySpec = new SecretKeySpec(Kmac, "AES");
        mac.init(macKeySpec);
        byte[] calculatedFullMac = mac.doFinal(macInput);
        byte[] calculatedMac = Arrays.copyOf(calculatedFullMac, MAC_LENGTH);

        // Compare calculated MAC with received MAC
        return Arrays.equals(calculatedMac, securePayload.getMac());
    }

    /**
     * Removes ISO/IEC 9797-1 padding method 2 from decrypted payload
     */
    private byte[] removePadding(byte[] paddedPayload) {
        // Find the padding start marker (0x80)
        int dataLength = paddedPayload.length;
        for (int i = paddedPayload.length - 1; i >= 0; i--) {
            if (paddedPayload[i] == (byte) 0x80) {
                dataLength = i;
                break;
            }
        }
        
        // Return the data without padding
        return Arrays.copyOf(paddedPayload, dataLength);
    }
}