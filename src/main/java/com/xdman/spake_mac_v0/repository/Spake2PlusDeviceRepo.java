package com.xdman.spake_mac_v0.repository;

import com.xdman.spake_mac_v0.domain.Spake2PlusDeviceData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface Spake2PlusDeviceRepo extends JpaRepository<Spake2PlusDeviceData, Long> {
  Spake2PlusDeviceData findByRequestId(String requestId);
}
