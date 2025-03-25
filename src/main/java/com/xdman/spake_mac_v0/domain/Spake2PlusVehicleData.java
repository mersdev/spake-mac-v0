package com.xdman.spake_mac_v0.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import lombok.Getter;
import lombok.Setter;

import java.math.BigInteger;

@Entity
@SequenceGenerator(name = "ID_SEQUENCE", sequenceName = "SPAKE_VEHICLE_SEQ", allocationSize = 1)
@Getter
@Setter
public class Spake2PlusVehicleData extends AbstractPersistable<Spake2PlusVehicleData> {

  @Column(name = "requestId")
  private String requestId;

  @Column(name = "w0", nullable = true)
  private BigInteger w0;

  @Column(name = "w1", nullable = true)
  private BigInteger w1;

}
