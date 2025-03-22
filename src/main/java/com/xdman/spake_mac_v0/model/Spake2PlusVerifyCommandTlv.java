package com.xdman.spake_mac_v0.model;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;
import lombok.Getter;
import lombok.Setter;

/**
 * SPAKE2+ VERIFY Command TLV format according to Table 5-6:
 *
 * Command format: 80 32 00 00 Lc [Data] 00
 *
 * Tag    Length     Description                                                       Field
 * 52h    65         Curve point Y of the SPAKE2+ protocol, prepended with 04h         Mandatory
 * 57h    16         Vehicle evidence M[1]                                             Mandatory
 */

@Getter
@Setter
public class Spake2PlusVerifyCommandTlv extends TlvBase{
  private byte[] curvePointY;      // 65 bytes (including 04h prefix)
  private byte[] vehicleEvidence;  // 16 bytes

  private enum Tags {
	CURVE_POINT_Y("52"),
	VEHICLE_EVIDENCE("57");

	public final BerTag tag;

	Tags(String hexString) {
	  this.tag = new BerTag(HexUtil.parseHex(hexString));
	}
  }


  @Override
  public Spake2PlusVerifyCommandTlv decode(String tlvString) {
	try {
	  // Remove command header and trailer
	  if (tlvString == null || tlvString.trim().isEmpty()) {
		throw new IllegalArgumentException("TLV string cannot be null or empty");
	  }

	  byte[] allBytes = HexUtil.parseHex(tlvString);
	  // Extract data part: after command header (5 bytes) and before trailer (1 byte)
	  byte[] dataPart = new byte[allBytes.length - 6];
	  System.arraycopy(allBytes, 5, dataPart, 0, dataPart.length);
	  BerTlvParser parser = new BerTlvParser();
	  BerTlvs tlvs = parser.parse(dataPart);

	  // Decode mandatory fields
	  BerTlv curvePointY = tlvs.find(Tags.CURVE_POINT_Y.tag);
	  if (curvePointY == null) {
		throw new IllegalArgumentException("Missing required field: Curve point Y");
	  }
	  setCurvePointY(curvePointY.getBytesValue());

	  BerTlv vehicleEvidence = tlvs.find(Tags.VEHICLE_EVIDENCE.tag);
	  if (vehicleEvidence == null) {
		throw new IllegalArgumentException("Missing required field: Vehicle evidence");
	  }
	  setVehicleEvidence(vehicleEvidence.getBytesValue());

	  return this;
	} catch (Exception e) {
	  throw new IllegalArgumentException("Failed to decode SPAKE2+ VERIFY Command: " + e.getMessage(), e);
	}
  }

  @Override
  public String encode() {
	try {
	  if(curvePointY == null || vehicleEvidence == null) {
		throw new IllegalArgumentException("Missing required fields: curvePointY and vehicleEvidence");
	  }
	  BerTlvBuilder builder = new BerTlvBuilder();

	  // Add mandatory fields
	  builder.addBytes(Tags.CURVE_POINT_Y.tag, curvePointY);
	  builder.addBytes(Tags.VEHICLE_EVIDENCE.tag, vehicleEvidence);

	  byte[] builderBytes = builder.buildArray();

	  // Construct full APDU
	  byte[] apdu = new byte[5 + builderBytes.length + 1];
	  apdu[0] = (byte) 0x80; // CLA
	  apdu[1] = (byte) 0x32; // INS
	  apdu[2] = (byte) 0x00; // P1
	  apdu[3] = (byte) 0x00; // P2
	  apdu[4] = (byte) builderBytes.length; // Lc
	  System.arraycopy(builderBytes, 0, apdu, 5, builderBytes.length);
	  apdu[5 + builderBytes.length] = (byte) 0x00; // Le

	  return HexUtil.toHexString(apdu).toUpperCase();

	} catch (Exception e) {
	  throw new IllegalArgumentException("Failed to encode SPAKE2+ VERIFY Command: " + e.getMessage(), e);
	}
  }
}
