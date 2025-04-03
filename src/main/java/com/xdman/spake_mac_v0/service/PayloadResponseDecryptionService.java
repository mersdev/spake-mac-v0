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
public class PayloadResponseDecryptionService {
    private static final byte[] ZERO_IV = new byte[16];
    private static final int MAC_LENGTH = 8;
    private static final byte RESPONSE_COUNTER_PREFIX = (byte) 0x80;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Decrypts response payload and verifies MAC according to GPC_SPE_014 section 6.2.7
     *
     * @param securePayload Encrypted response data with MAC
     * @param Kenc Encryption key
     * @param Krmac Response MAC key
     * @param previousMacChaining MAC chaining value from command
     * @return Decrypted response payload
     */
    public byte[] decryptResponsePayload(SecurePayload securePayload, byte[] Kenc, byte[] Krmac, byte[] previousMacChaining)
            throws NoSuchAlgorithmException, javax.crypto.NoSuchPaddingException, java.security.InvalidKeyException,
            javax.crypto.IllegalBlockSizeException, javax.crypto.BadPaddingException,
            java.security.InvalidAlgorithmParameterException, NoSuchProviderException {
        
        // Validate inputs
        if (securePayload == null) {
            throw new IllegalArgumentException("SecurePayload must not be null");
        }
        if (securePayload.getCounter() < 1) {
            throw new IllegalArgumentException("Counter must be between 1 and 255");
        }
        if (Kenc == null || Kenc.length != 16) {
            throw new IllegalArgumentException("Kenc must be 16 bytes");
        }
        if (Krmac == null || Krmac.length != 16) {
            throw new IllegalArgumentException("Krmac must be 16 bytes");
        }

        try {
            // Verify MAC
            byte[] macInput = new byte[previousMacChaining == null ? securePayload.getEncryptedPayload().length : 
                    previousMacChaining.length + securePayload.getEncryptedPayload().length];
            if (previousMacChaining != null) {
                System.arraycopy(previousMacChaining, 0, macInput, 0, previousMacChaining.length);
                System.arraycopy(securePayload.getEncryptedPayload(), 0, macInput, previousMacChaining.length, 
                        securePayload.getEncryptedPayload().length);
            } else {
                System.arraycopy(securePayload.getEncryptedPayload(), 0, macInput, 0, 
                        securePayload.getEncryptedPayload().length);
            }

            // Calculate MAC using CMAC with Krmac
            Mac mac = Mac.getInstance("AESCMAC", "BC");
            SecretKeySpec rmacKeySpec = new SecretKeySpec(Krmac, "AES");
            mac.init(rmacKeySpec);
            byte[] calculatedMac = Arrays.copyOf(mac.doFinal(macInput), MAC_LENGTH);

            // Verify MAC
            if (!Arrays.equals(calculatedMac, securePayload.getMac())) {
                throw new SecurityException("MAC verification failed");
            }

            // Create response counter block (0x80 || 0x00...00 || counter)
            byte[] counterBlock = Arrays.copyOf(ZERO_IV, 16);
            counterBlock[0] = RESPONSE_COUNTER_PREFIX; // Set 0x80 prefix
            counterBlock[15] = securePayload.getCounter();

            // Decrypt payload using AES-CBC with response counter block as IV
            SecretKeySpec encKeySpec = new SecretKeySpec(Kenc, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, encKeySpec, new IvParameterSpec(counterBlock));
            byte[] decryptedPayload = cipher.doFinal(securePayload.getEncryptedPayload());

            // Remove ISO/IEC 9797-1 padding method 2
            return unpadPayload(decryptedPayload);

        } catch (SecurityException e) {
            log.error("MAC verification failed", e);
            throw e;
        } catch (Exception e) {
            log.error("Error decrypting response payload", e);
            throw e;
        }
    }

    /**
     * Removes ISO/IEC 9797-1 padding method 2 from decrypted payload
     */
    private byte[] unpadPayload(byte[] paddedPayload) {
        int i = paddedPayload.length - 1;
        while (i >= 0 && paddedPayload[i] == 0) {
            i--;
        }
        if (i < 0 || paddedPayload[i] != (byte) 0x80) {
            throw new IllegalArgumentException("Invalid padding");
        }
        return Arrays.copyOf(paddedPayload, i);
    }
}