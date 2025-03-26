package com.xdman.spake_mac_v0.repository;

import com.xdman.spake_mac_v0.domain.Spake2PlusVehicleData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Spake2PlusVehicleRepo extends JpaRepository<Spake2PlusVehicleData, Long> {
  Spake2PlusVehicleData findByRequestId(String requestId);
}
