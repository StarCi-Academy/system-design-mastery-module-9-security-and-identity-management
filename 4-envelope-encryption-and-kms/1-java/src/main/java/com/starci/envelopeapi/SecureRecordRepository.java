package com.starci.envelopeapi;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SecureRecordRepository extends JpaRepository<SecureRecord, Integer> {
}
