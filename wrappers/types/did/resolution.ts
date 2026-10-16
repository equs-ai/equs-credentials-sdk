export type ResolutionOptionsParameter = {
    /**
     * Service ID from the DID document.
     */
    service?: string,

    /**
     * Resource at a service endpoint, which is selected from a
     * DID document by using the service parameter.
     */
    relative_ref?: string,

    /**
     * Specific version of a DID document to be resolved (the version ID could
     * be sequential, or a UUID, or method-specific).
     */
    version_id?: string,


    /**
     * Version timestamp of a DID document to be resolved. That is, the DID
     * document that was valid for a DID at a certain time.
     */
    version_time?: string,

    /**
     *
     * Resource hash of the DID document to add integrity protection, as
     * specified in [HASHLINK](https://www.w3.org/TR/did-core/#bib-hashlink).
     *
     * This parameter is non-normative.
     */
    hl?: string,

    /**
     *
     * Expected public key format (non-standard option).
     *
     * Defined by <https://w3c-ccg.github.io/did-method-key>.
     */
    public_key_format?: string,

    /**
     * Additional parameters.
     */
    additional: Record<string, null | string | string[]>,
}