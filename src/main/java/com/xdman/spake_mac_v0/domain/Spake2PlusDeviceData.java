package com.xdman.spake_mac_v0.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;

@Entity
@SequenceGenerator(name = "ID_SEQUENCE", sequenceName = "SPAKE_DEVICE_SEQ", allocationSize = 1)
@Getter
@Setter
public class Spake2PlusDeviceData extends AbstractPersistable<Spake2PlusDeviceData> {

  @Column(name = "requestId")
  private String requestId;

  @Column(name = "password")
  private String password;

  @Column(name = "w0")
  private BigInteger w0;

  @Column(name = "w1")
  private BigInteger w1;

  @Column(name = "x")
  private BigInteger x;
}
