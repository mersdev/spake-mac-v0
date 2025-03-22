package com.xdman.spake_mac_v0.model;

import java.util.Base64;

public abstract class TlvBase {
  protected static Base64.Encoder b64Encoder = Base64.getEncoder();
  protected static Base64.Decoder b64Decoder = Base64.getDecoder();

  public abstract Object decode(String tlvString);

  public abstract String encode();
}
