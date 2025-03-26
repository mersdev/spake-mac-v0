package com.xdman.spake_mac_v0.model;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;
import lombok.Getter;
import lombok.Setter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * SPAKE2+ REQUEST Command TLV format according to Digital Key Technical Specification Release 3.
 *
 * Command format: 80 30 00 00 Lc [Data] 00
 *
 * Tag    Length     Description                                          Field
 * 5Bh    2 × n     Supported V-OD-FW versions (ver.high | ver.low)     Mandatory
 * 5Ch    2 × m     Supported Digital Key protocol versions              Mandatory
 * 5Eh    2 × o     Supported V-D-BT versions                           Optional
 * 7F50h  32        Scrypt configuration parameters                      Mandatory
 * C0h    16        Cryptographic salt (s)                              Mandatory
 * C1h    4         Scrypt cost parameter (Nscrypt)                     Mandatory
 * C2h    2         Block size parameter (r)                            Mandatory
 * C3h    2         Parallelization parameter (p)                       Mandatory
 * D6h    2         Vehicle Brand                                       Mandatory
 */

@Getter
@Setter
public class Spake2PlusRequestCommandTlv extends TlvBase{
  private byte[] vodFwVersions;          // Mandatory - V-OD-FW versions
  private byte[] dkProtocolVersions;     // Mandatory - Digital Key protocol versions
  private byte[] btVersions;             // Optional - V-D-BT versions
  private byte[] scryptConfig;           // Mandatory - 32 bytes
  private String cryptographicSalt;      // Mandatory - 16 bytes
  private Integer scryptCost;            // Mandatory - 4 bytes
  private Integer blockSize;             // Mandatory - 2 bytes
  private Integer parallelization;       // Mandatory - 2 bytes
  private String vehicleBrand;           // Mandatory - 2 bytes (hex string)


  private enum Tags {
    VOD_FW_VERSIONS("5B"),
    DK_PROTOCOL_VERSIONS("5C"),
    BT_VERSIONS("5E"),
    SCRYPT_CONFIG("7F50"),
    CRYPTOGRAPHIC_SALT("C0"),
    SCRYPT_COST("C1"),
    BLOCK_SIZE("C2"),
    PARALLELIZATION("C3"),
    VEHICLE_BRAND("D6");

    public final BerTag tag;

    Tags(String hexString) {
      this.tag = new BerTag(HexUtil.parseHex(hexString));
    }
  }

  @Override
  public Spake2PlusRequestCommandTlv decode(String tlvString) {
    try {
      if (tlvString == null || tlvString.trim().isEmpty()) {
        throw new IllegalArgumentException("TLV string cannot be null or empty");
      }

      byte[] allBytes = HexUtil.parseHex(tlvString);
      // Extract data part: after command header (5 bytes) and before trailer (1 byte)
      byte[] dataPart = new byte[allBytes.length - 6];
      System.arraycopy(allBytes, 5, dataPart, 0, dataPart.length);
      BerTlvParser parser = new BerTlvParser();
      BerTlvs tlvs = parser.parse(dataPart);

      // Handle mandatory fields with validation
      BerTlv vodFwVersionsTlv = tlvs.find(Tags.VOD_FW_VERSIONS.tag);
      if (vodFwVersionsTlv == null) {
        throw new IllegalArgumentException("Missing mandatory field: VOD firmware versions");
      }
      setVodFwVersions(vodFwVersionsTlv.getBytesValue());

      BerTlv dkProtocolVersionsTlv = tlvs.find(Tags.DK_PROTOCOL_VERSIONS.tag);
      if (dkProtocolVersionsTlv == null) {
        throw new IllegalArgumentException("Missing mandatory field: DK protocol versions");
      }
      setDkProtocolVersions(dkProtocolVersionsTlv.getBytesValue());

      // Handle optional BT versions
      BerTlv btVersionsTlv = tlvs.find(Tags.BT_VERSIONS.tag);
      if (btVersionsTlv != null) {
        setBtVersions(btVersionsTlv.getBytesValue());
      }

      // Handle constructed Scrypt configuration TLV
      BerTlv scryptTlv = tlvs.find(Tags.SCRYPT_CONFIG.tag);
      if (scryptTlv != null && scryptTlv.isConstructed()) {
        // Get the nested TLVs directly from the constructed TLV
        List<BerTlv> scryptTlvs = scryptTlv.getValues();

        // Extract all Scrypt parameters from the nested TLVs
        for (BerTlv tlv : scryptTlvs) {
          if (tlv.getTag().equals(Tags.CRYPTOGRAPHIC_SALT.tag)) {
            this.cryptographicSalt = HexUtil.toHexString(tlv.getBytesValue());
          } else if (tlv.getTag().equals(Tags.SCRYPT_COST.tag)) {
            this.scryptCost = ByteBuffer.wrap(tlv.getBytesValue()).getInt();
          } else if (tlv.getTag().equals(Tags.BLOCK_SIZE.tag)) {
            this.blockSize = (int) ByteBuffer.wrap(tlv.getBytesValue()).getShort();
          } else if (tlv.getTag().equals(Tags.PARALLELIZATION.tag)) {
            this.parallelization = (int) ByteBuffer.wrap(tlv.getBytesValue()).getShort();
          }
        }

        // Validate all required Scrypt parameters are present
        if (cryptographicSalt == null || scryptCost == null ||
          blockSize == null || parallelization == null) {
          throw new IllegalArgumentException("Missing required Scrypt parameters");
        }

        // Combine all parameters into scryptConfig
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
          outputStream.write(HexUtil.parseHex(cryptographicSalt));
          outputStream.write(ByteBuffer.allocate(4).putInt(scryptCost).array());
          outputStream.write(ByteBuffer.allocate(2).putShort(blockSize.shortValue()).array());
          outputStream.write(ByteBuffer.allocate(2).putShort(parallelization.shortValue()).array());
          this.scryptConfig = outputStream.toByteArray();
        } catch (IOException e) {
          throw new IllegalArgumentException("Failed to combine Scrypt parameters", e);
        }
      } else {
        throw new IllegalArgumentException("Invalid or missing Scrypt configuration");
      }

      // Handle vehicle brand
      BerTlv vehicleBrandTlv = tlvs.find(Tags.VEHICLE_BRAND.tag);
      if (vehicleBrandTlv == null) {
        throw new IllegalArgumentException("Missing mandatory field: Vehicle brand");
      }
      setVehicleBrand(HexUtil.toHexString(vehicleBrandTlv.getBytesValue()));

      return this;
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to decode SPAKE2+ REQUEST Command: " + e.getMessage(), e);
    }
  }

  @Override
  public String encode() {
    try {
      // Validate all mandatory fields are present
      if (vodFwVersions == null || dkProtocolVersions == null ||
        cryptographicSalt == null || scryptCost == null ||
        blockSize == null || parallelization == null ||
        vehicleBrand == null) {
        throw new IllegalArgumentException("Mandatory field is missing");
      }


      BerTlvBuilder dataBuilder = new BerTlvBuilder();
      dataBuilder.addBytes(new BerTag(0x5B), vodFwVersions);
      dataBuilder.addBytes(new BerTag(0x5C), dkProtocolVersions);
      BerTag tag7F50 = new BerTag(new byte[]{(byte) 0x7F, (byte) 0x50});

      BerTlvBuilder scryptConfig = new BerTlvBuilder(tag7F50);
      scryptConfig.addHex(new BerTag(0xC0), cryptographicSalt);
      scryptConfig.addHex(new BerTag(0xC1), String.format("%08X", scryptCost));
      scryptConfig.addHex(new BerTag(0xC2), String.format("%04X", blockSize)); // Convert to hex string with padding
      scryptConfig.addHex(new BerTag(0xC3), String.format("%04X", parallelization)); // Convert to hex string with padding
      dataBuilder.add(scryptConfig);

      dataBuilder.addHex(new BerTag(0xD6), vehicleBrand);

      // Build data part
      byte[] dataBytes = dataBuilder.buildArray();
      // Construct full APDU
      byte[] apdu = new byte[5 + dataBytes.length + 1];
      apdu[0] = (byte) 0x80; // CLA
      apdu[1] = (byte) 0x30; // INS
      apdu[2] = (byte) 0x00; // P1
      apdu[3] = (byte) 0x00; // P2
      apdu[4] = (byte) dataBytes.length; // Lc
      System.arraycopy(dataBytes, 0, apdu, 5, dataBytes.length);
      apdu[5 + dataBytes.length] = (byte) 0x00; // Le

      return HexUtil.toHexString(apdu).toUpperCase();
    } catch (Exception e) {
      throw new IllegalArgumentException("Failed to encode SPAKE2+ REQUEST Command: " + e.getMessage(), e);
    }
  }
}
