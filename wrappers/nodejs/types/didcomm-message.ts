export interface DIDCommMessage {
    /**
     * Message id. Must be unique to the sender.
     */
    id: string,

    /**
     * Must be "application/didcomm-plain+json"
     */
    typ: string,

    /**
     * Message type attribute value MUST be a valid Message Type URI,
     * that when resolved gives human readable information about the message.
     * The attribute’s value also informs the content of the message,
     * or example the presence of other attributes and how they should be processed.
     */
    type: string,

    /**
     * Message body.
     */
    body: any,

    /**
     * Sender identifier. The from attribute MUST be a string that is a valid DID
     * or DID URL (without the fragment component) which identifies the sender of the message.
     */
    from?: string,

    /**
     * Identifier(s) for recipients. MUST be an array of strings where each element
     * is a valid DID or DID URL (without the fragment component) that identifies a member
     * of the message’s intended audience.
     */
    to?: Array<string>,

    /**
     * Uniquely identifies the thread that the message belongs to.
     * If not included the id property of the message MUST be treated as the value of the `thid`.
     */
    thid?: string,

    /**
     * If the message is a child of a thread the `pthid`
     * will uniquely identify which thread is the parent.
     */
    pthid?: string,

    /**
     * Custom message headers.
     */
    [extra_header: string]: any

    /**
     * The attribute is used for the sender
     * to express when they created the message, expressed in
     * UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     * This attribute is informative to the recipient, and may be relied on by protocols.
     */
    created_time?: number,

    /**
     * The expires_time attribute is used for the sender to express when they consider
     * the message to be expired, expressed in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     * This attribute signals when the message is considered no longer valid by the sender.
     * When omitted, the message is considered to have no expiration by the sender.
     */
    expires_time?: number,

    /**
     * from_prior is a compactly serialized signed JWT containing FromPrior value
     */
    from_prior?: string,

    /**
     * Message attachments
     */
    attachments?: Array<DIDCommAttachment>,
}

export interface DIDCommAttachment {
    /**
     * A JSON object that gives access to the actual content of the attachment.
     * Can be based on base64, json or external links.
     */
    data: AttachmentData,

    /**
     * Identifies attached content within the scope of a given message.
     * Recommended on appended attachment descriptors. Possible but generally unused
     * on embedded attachment descriptors. Never required if no references to the attachment
     * exist; if omitted, then there is no way to refer to the attachment later in the thread,
     * in error messages, and so forth. Because id is used to compose URIs, it is recommended
     * that this name be brief and avoid spaces and other characters that require URI escaping.
     */
    id?: string,

    /**
     * A human-readable description of the content.
     */
    description?: string,

    /**
     * A hint about the name that might be used if this attachment is persisted as a file.
     * It is not required, and need not be unique. If this field is present and mime-type is not,
     * the extension on the filename may be used to infer a MIME type.
     */
    filename?: string,

    /**
     * Describes the MIME type of the attached content.
     */
    media_type?: string,

    /**
     * Describes the format of the attachment if the mime_type is not sufficient.
     */
    format?: string,

    /**
     * A hint about when the content in this attachment was last modified
     * in UTC Epoch Seconds (seconds since 1970-01-01T00:00:00Z UTC).
     */
    lastmod_time?: number,

    /**
     * Mostly relevant when content is included by reference instead of by value.
     * Lets the receiver guess how expensive it will be, in time, bandwidth, and storage,
     * to fully fetch the attachment.
     */
    byte_count?: number,
}

export type AttachmentData = Base64AttachmentData | JsonAttachmentData | LinksAttachmentData

export interface Base64AttachmentData {
    /**
     * Base64-encoded data, when representing arbitrary content inline.
     */
    base64: string,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}

export interface JsonAttachmentData {
    /**
     * Directly embedded JSON data.
     */
    json: any,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}

export interface LinksAttachmentData {
    /**
     * A list of one or more locations at which the content may be fetched.
     */
    links: Array<string>,

    /**
     * The hash of the content encoded in multi-hash format. Used as an integrity check for the attachment.
     */
    hash: string,

    /**
     * A JSON Web Signature over the content of the attachment.
     */
    jws?: string,
}
