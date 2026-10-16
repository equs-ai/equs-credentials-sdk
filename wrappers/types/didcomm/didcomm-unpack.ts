export interface UnpackOptions {
    /**
     * Whether the plaintext must be decryptable by all keys resolved by the secrets resolver.
     * False by default.
     */
    expect_decrypt_by_all_keys?: boolean,

    /**
     * If `true` and the packed message is a `Forward`
     * wrapping a plaintext packed for the given recipient, then both Forward and packed plaintext are unpacked automatically,
     * and the unpacked plaintext will be returned instead of unpacked Forward.
     * False by default.
     */
    unwrap_re_wrapping_forward?: boolean,
}

export interface UnpackMetadata {
    /**
     * Whether the plaintext has been encrypted.
     */
    encrypted: boolean,

    /**
     * Whether the plaintext has been authenticated.
     */
    authenticated: boolean,

    /**
     * Whether the plaintext has been signed.
     */
    non_repudiation: boolean,

    /**
     * Whether the sender ID was hidden or protected.
     */
    anonymous_sender: boolean,

    /**
     * Whether the plaintext was re-wrapped in a forward message by a mediator.
     */
    re_wrapped_in_forward: boolean,

    /**
     * Key ID of the sender used for authentication encryption
     * if the plaintext has been authenticated and encrypted.
     */
    encrypted_from_kid?: string,

    /**
     * Target key IDS for encryption if the plaintext has been encrypted.
     */
    encrypted_to_kids?: Array<string>,

    /**
     * Key ID used for signature if the plaintext has been signed.
     */
    sign_from: string,

    /**
     * Key ID used for from_prior header signature if from_prior header is present
     */
    from_prior_issuer_kid?: string,

    /**
     * Algorithm used for authenticated encryption.
     * Default "A256cbcHs512Ecdh1puA256kw"
     */
    enc_alg_auth?: "A256cbcHs512Ecdh1puA256kw",

    /**
     * Algorithm used for anonymous encryption.
     * Default "Xc20pEcdhEsA256kw"
     */
    enc_alg_anon?: "A256cbcHs512EcdhEsA256kw" | "Xc20pEcdhEsA256kw" | "A256gcmEcdhEsA256kw",

    /**
     * Algorithm used for message signing.
     */
    sign_alg?: "EdDSA" | "ES256" | "ES256K",

    /**
     * If the plaintext has been signed, the JWS is returned for non-repudiation purposes.
     */
    signed_message?: string,

    /**
     * If plaintext contains from_prior header, its unpacked value is returned
     */
    from_prior?: FromPrior,
}

export interface FromPrior {
    /**
     * new DID after rotation
     */
    iss: string,

    /**
     * prior DID
     */
    sub: string,

    /**
     * Datetime of the DID rotation
     */
    iat?: number,
}