package com.xdman.spake_mac_v0.domain;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.Version;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.util.ProxyUtils;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.function.Consumer;

@MappedSuperclass
public abstract class AbstractPersistable<T extends AbstractPersistable<T>> {
  @Id
  @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ID_SEQUENCE")
  private Long id;

  public Long getId() {
	return id;
  }

  @CreationTimestamp
  @Column(updatable = false)
  protected LocalDateTime createdAt;

  @UpdateTimestamp
  protected LocalDateTime updatedAt;

  @Version
  protected long version = 0;

  @Override
  public boolean equals(Object other) {
	if (this == other) {
	  return true;
	}
	if (other == null || getClass() != ProxyUtils.getUserClass(other)) {
	  return false;
	}

	AbstractPersistable<?> that = (AbstractPersistable<?>) other;

	return Objects.equals(id, that.id);
  }

  @Override
  public int hashCode() {
	return 1337;
  }

  @Override
  public String toString() {
	return "Entity of type " + getClass().getName() + " with id: " + id;
  }

  public void apply(Consumer<T> consumer) {
	consumer.accept((T) this);
  }

}
