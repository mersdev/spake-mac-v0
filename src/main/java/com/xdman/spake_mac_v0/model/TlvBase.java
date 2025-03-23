package com.xdman.spake_mac_v0.model;

import java.util.Base64;

public abstract class TlvBase {

  public abstract Object decode(String tlvString);

  public abstract String encode();
}
