package com.xdman.spake_mac_v0.model.tlv;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;
import com.xdman.spake_mac_v0.model.TlvBase;
import lombok.Getter;
import lombok.Setter;

/**
 * SPAKE2+ VERIFY Response TLV format according to Table 5-7:
 *
 * Response format: [Data] 90 00
 *
 * Tag    Length     Description                                          Field
 * 58h    16         Device evidence M[2]                               Mandatory
 */

@Getter
@Setter
public class Spake2PlusVerifyResponseTlv extends TlvBase {
  private byte[] deviceEvidence;   // 16 bytes

  private enum Tags {
	DEVICE_EVIDENCE("58");

	public final BerTag tag;

	Tags(String hexString) {
	  this.tag = new BerTag(HexUtil.parseHex(hexString));
	}
  }

  @Override
  public Spake2PlusVerifyResponseTlv decode(String tlvString) {
	try{
	  if (tlvString == null || !tlvString.endsWith("9000")) {
		throw new IllegalArgumentException("Invalid response format: must end with 9000");
	  }

	  String tlvHex = tlvString.substring(0, tlvString.length() - 4);
	  byte[] tlvBytes = HexUtil.parseHex(tlvHex);
	  BerTlvParser parser = new BerTlvParser();
	  BerTlvs tlvs = parser.parse(tlvBytes, 0, tlvBytes.length);

	  BerTlv deviceEvidence = tlvs.find(Tags.DEVICE_EVIDENCE.tag);
	  setDeviceEvidence(deviceEvidence.getBytesValue());

	  return this;
	}
	catch (Exception e) {
	  throw new IllegalArgumentException("Failed to decode SPAKE2+ VERIFY Response: " + e.getMessage(), e);
	}
  }

  @Override
  public String encode() {
	try{
	  BerTlvBuilder builder = new BerTlvBuilder();
	  builder.addBytes(Tags.DEVICE_EVIDENCE.tag, deviceEvidence);

	  byte[] builderBytes = builder.buildArray();
	  return HexUtil.toHexString(builderBytes).toUpperCase() + "9000";
	}
	catch (Exception e) {
	  throw new IllegalArgumentException("Failed to encode SPAKE2+ VERIFY Response: " + e.getMessage(), e);
	}
  }
}
