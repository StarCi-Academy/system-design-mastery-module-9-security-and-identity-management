package com.starci.envelopeapi;

import jakarta.persistence.*;

/**
 * Stores ONLY ciphertext + the wrapped DEK. No plaintext, no raw DEK — a DB dump is useless
 * without the KEK held in Vault Transit.
 */
@Entity
@Table(name = "secure_records")
public class SecureRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "wrapped_dek", columnDefinition = "text")
    private String wrappedDek;

    @Column(columnDefinition = "text")
    private String iv;

    @Column(name = "auth_tag", columnDefinition = "text")
    private String authTag;

    @Column(columnDefinition = "text")
    private String ciphertext;

    public Integer getId() { return id; }
    public String getWrappedDek() { return wrappedDek; }
    public void setWrappedDek(String v) { this.wrappedDek = v; }
    public String getIv() { return iv; }
    public void setIv(String v) { this.iv = v; }
    public String getAuthTag() { return authTag; }
    public void setAuthTag(String v) { this.authTag = v; }
    public String getCiphertext() { return ciphertext; }
    public void setCiphertext(String v) { this.ciphertext = v; }
}
