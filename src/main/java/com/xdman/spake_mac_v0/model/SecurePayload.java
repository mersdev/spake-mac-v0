package com.xdman.spake_mac_v0.model;

import lombok.Data;

@Data
public class SecurePayload {
    private byte[] encryptedPayload;  // Ciphered Command Data Field
    private byte[] mac;               // C-MAC (8 bytes)
    private byte[] macChainingValue;  // MAC Chaining Value for next command
    private byte counter;            // 1-byte counter (01h for first command, up to max FFh)
}