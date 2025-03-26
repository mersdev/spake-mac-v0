package com.xdman.spake_mac_v0.model;

import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvBuilder;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import com.payneteasy.tlv.HexUtil;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class Spake2PlusRequestResponseTlv extends TlvBase{
  private byte[] curvePointX;           // 65 bytes (including 0x04 prefix)
  private byte[] selectedVodFwVersion;  // 2 bytes, conditional

  private enum Tags {
	CURVE_POINT_X("50"),
	SELECTED_VOD_FW_VERSION("5F");

	public final BerTag tag;

	Tags(String hexString) {
	  this.tag = new BerTag(HexUtil.parseHex(hexString));
	}
  }

  @Override
  public Spake2PlusRequestResponseTlv decode(String tlvString) {
	try {
	  // Remove headers and trailers if present
	  if (tlvString == null || !tlvString.endsWith("9000")) {
		throw new IllegalArgumentException("Invalid response format: must end with 9000");
	  }

	  String tlvHex = tlvString.substring(0, tlvString.length() - 4);
	  byte[] tlvBytes = HexUtil.parseHex(tlvHex);
	  BerTlvParser parser = new BerTlvParser();
	  BerTlvs tlvs = parser.parse(tlvBytes, 0, tlvBytes.length);

	  // Decode mandatory field
	  BerTlv curvePointX = tlvs.find(Tags.CURVE_POINT_X.tag);
	  if(curvePointX == null) {
		throw new IllegalArgumentException("Missing mandatory field: Curve Point X");
	  }
	  setCurvePointX(curvePointX.getBytesValue());

	  // Decode conditional field
	  BerTlv selectedVodFwVersion = tlvs.find(Tags.SELECTED_VOD_FW_VERSION.tag);
	  if (selectedVodFwVersion != null) {
		setSelectedVodFwVersion(selectedVodFwVersion.getBytesValue());
	  }

	  return this;
	} catch (Exception e) {
	  throw new IllegalArgumentException("Failed to decode SPAKE2+ REQUEST Response: " + e.getMessage(), e);
	}
  }

  @Override
  public String encode() {
	try {
	  validateCurvePoint(curvePointX);

	  BerTlvBuilder builder = new BerTlvBuilder();
	  builder.addBytes(Tags.CURVE_POINT_X.tag, curvePointX);
	  if (selectedVodFwVersion != null) {
		builder.addBytes(Tags.SELECTED_VOD_FW_VERSION.tag, selectedVodFwVersion);
	  }

	  byte[] builderBytes = builder.buildArray();
	  return HexUtil.toHexString(builderBytes).toUpperCase() + "9000";

	} catch (Exception e) {
	  throw new IllegalArgumentException("Failed to encode SPAKE2+ REQUEST Response: " + e.getMessage(), e);
	}
  }

  private void validateCurvePoint(byte[] curvePoint) {
	if (curvePoint == null) {
	  throw new IllegalArgumentException("Curve point X cannot be null");
	}
	if (curvePoint.length != 65) {
	  throw new IllegalArgumentException("Curve point X must be 65 bytes (including 0x04 prefix)");
	}
	if (curvePoint[0] != 0x04) {
	  throw new IllegalArgumentException("Curve point X must start with 0x04 prefix");
	}
  }
}
