/**
 * The DcqlClaim are objects to describe/filter the claims to include/fetch as part of credential
 */
export interface DcqlClaim {
    id?: string,
    path?: Array<string | number | null>,
    namespace?: string,
    claim_name?: string,
    values?: Array<string | number | boolean>,
}

/**
 * DcqlCredential is an object to describe a credential to fetch. Like what kind of claims it should have and in what format
 */
export interface DcqlCredential {
    id: string,
    format: string,
    meta?: any,
    claims?: Array<DcqlClaim>,
    claim_sets?: Array<Array<string>>,
}

/**
 * DcqlCredentialSet is used to list all the matching/satisfactory sets of credentials.
 * Example: required = true and options = [["1","2"], ["4","5"]] means either send "1" and "2" credentials or "4" and "5" credentials.
 * Either pair is fine. Note that the ["1","2"] above is a set of ids(not indexes).
 */
export interface DcqlCredentialSet {
    options?: Array<Array<string>>,
    required?: boolean,
    purpose?: string
}

/**
 * Dcql is used to query the needed credentials from the holder. The rules are here:
 * @see {@link https://openid.net/specs/openid-4-verifiable-presentations-1_0-22.html#name-digital-credentials-query-l|Digital Credentials Query Language(DCQL)}
 */
export interface Dcql {
    credentials: Array<DcqlCredential>,
    credential_sets?: Array<DcqlCredentialSet>
}