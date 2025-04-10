package com.xdman.spake_mac_v0.model.tlv;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.SecurePayload;
import com.xdman.spake_mac_v0.model.TlvBase;
import com.xdman.spake_mac_v0.service.PayloadResponseDecryptionService;
import com.xdman.spake_mac_v0.service.PayloadResponseEncryptionService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * SPAKE2+ VERIFY Response TLV format according to Table 5-7:
 *
 * Response format: [Data] 90 00
 *
 * Tag    Length     Description                                          Field
 * 55h    0         Completion of Digital Key Data Sending                Mandatory
 */
@Getter
@Setter
public class WriteCompletionOfDigitalKeyDataSending extends TlvBase {

    @Autowired
    private PayloadResponseEncryptionService encryptionService;

    @Autowired
    private PayloadResponseDecryptionService decryptionService;

    private byte[] Kenc;  // Encryption key
    private byte[] Krmac; // Response MAC key
    private byte counter = 1; // Starting counter value
    private byte[] previousMacChaining; // MAC chaining value from previous operation

    private enum Tags {
        COMPLETION("55");

        public final BerTag tag;

        Tags(String hexString) {
            this.tag = new BerTag(HexUtil.parseHex(hexString));
        }
    }

    @Override
    public Object decode(String tlvString) {
        try {
            if (tlvString == null || tlvString.trim().isEmpty()) {
                throw new IllegalArgumentException("TLV string cannot be null or empty");
            }

            // Parse the encrypted payload and MAC from the input string
            byte[] encryptedData = HexUtil.parseHex(tlvString);
            
            // Create SecurePayload object
            SecurePayload securePayload = new SecurePayload();
            securePayload.setEncryptedPayload(encryptedData);
            securePayload.setCounter(counter);
            
            // Decrypt the payload
            byte[] decryptedData = decryptionService.decryptResponsePayload(
                securePayload, Kenc, Krmac, previousMacChaining
            );
            
            // Verify the decrypted TLV format [Data] 90 00
            if (decryptedData.length != 4 || decryptedData[0] != (byte) 0x55 || decryptedData[1] != 0x00 ||
                decryptedData[2] != (byte) 0x90 || decryptedData[3] != 0x00) {
                throw new IllegalArgumentException("Invalid Completion of Digital Key Data Sending format");
            }

            return this;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to decode Completion of Digital Key Data Sending: " + e.getMessage(), e);
        }
    }

    @Override
    public String encode() {
        try {
            // Create TLV data
            BerTlvBuilder builder = new BerTlvBuilder();
            builder.addEmpty(new BerTag(0x55)); // Tag 55h with zero length
            byte[] tlvBytes = builder.buildArray();
            
            // Construct APDU response format [Data] 90 00
            byte[] apdu = new byte[tlvBytes.length + 2];
            System.arraycopy(tlvBytes, 0, apdu, 0, tlvBytes.length);
            apdu[tlvBytes.length] = (byte) 0x90; // SW1
            apdu[tlvBytes.length + 1] = (byte) 0x00; // SW2
            
            // Encrypt the APDU
            SecurePayload securePayload = encryptionService.encryptResponsePayload(
                apdu, Kenc, Krmac, counter, previousMacChaining
            );
            
            // Store the MAC chaining value for next operation
            this.previousMacChaining = securePayload.getMacChainingValue();
            
            // Increment counter for next operation
            this.counter++;
            
            return HexUtil.toHexString(securePayload.getEncryptedPayload()).toUpperCase();
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encode Completion of Digital Key Data Sending: " + e.getMessage(), e);
        }
    }
}
