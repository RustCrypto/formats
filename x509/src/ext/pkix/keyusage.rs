use flagset::{flags, FlagSet};

flags! {
    /// Key usage flags as defined in [RFC 5280 Section 4.2.1.3].
    ///
    /// ```text
    /// KeyUsage ::= BIT STRING {
    ///      digitalSignature        (0),
    ///      nonRepudiation          (1),  -- recent editions of X.509 have
    ///                                    -- renamed this bit to contentCommitment
    ///      keyEncipherment         (2),
    ///      dataEncipherment        (3),
    ///      keyAgreement            (4),
    ///      keyCertSign             (5),
    ///      cRLSign                 (6),
    ///      encipherOnly            (7),
    ///      decipherOnly            (8)
    /// }
    /// ```
    ///
    /// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    #[allow(missing_docs)]
    pub enum KeyUsages: u16 {
        DigitalSignature = 1 << 0,
        NonRepudiation = 1 << 1,
        KeyEncipherment = 1 << 2,
        DataEncipherment = 1 << 3,
        KeyAgreement = 1 << 4,
        KeyCertSign = 1 << 5,
        CRLSign = 1 << 6,
        EncipherOnly = 1 << 7,
        DecipherOnly = 1 << 8,
    }
}

/// KeyUsage as defined in [RFC 5280 Section 4.2.1.3].
///
/// This extension is identified by the [`PKIX_CE_KEY_USAGE`](constant.PKIX_CE_KEY_USAGE.html) OID.
///
/// [RFC 5280 Section 4.2.1.3]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
pub type KeyUsage<'a> = FlagSet<KeyUsages>;
