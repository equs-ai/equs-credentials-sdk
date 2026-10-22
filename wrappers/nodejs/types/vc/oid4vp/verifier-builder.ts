import {
  buildVpVerifier,
  ClientId,
  ClientMetadata,
  contextEnsuredKms,
  contextEnsuredNonceHandler,
  CredentialClassification,
  DIDResolver,
  KeyMetadata,
  Kms,
  NonceHandler,
  ReqwestHttpClient,
  TrustAnchor,
} from "../../../";
import { OID4VPVerifier } from "./verifier";

export class OID4VPVerifierBuilder {
  private readonly kms: Kms;
  private readonly nonceHandler: NonceHandler;
  private readonly keyMetadata: KeyMetadata;
  private readonly clientId: ClientId;
  private clientMetadata?: ClientMetadata;
  private httpClient?: ReqwestHttpClient;
  private didResolver?: DIDResolver;
  private trustedRootCertificates?: Array<Uint8Array>;
  private x509CertificateChain?: Uint8Array;
  private trustAnchors?: Array<TrustAnchor>;
  private issuerTrustMode?: "enforce" | "report";
  private credentialClassification?: CredentialClassification;
  private rolelessAnchors?: "all_categories" | "eaa_only";

  constructor(kms: Kms, NonceHandler: NonceHandler, keyMetadata: KeyMetadata, clientId: ClientId) {
    this.kms = kms;
    this.nonceHandler = NonceHandler;
    this.keyMetadata = keyMetadata;
    this.clientId = clientId;
  }

  withClientMetadata(clientMetadata: ClientMetadata): this {
    this.clientMetadata = clientMetadata;
    return this;
  }

  withHttpClient(httpClient: ReqwestHttpClient): this {
    this.httpClient = httpClient;
    return this;
  }

  withDidResolver(didResolver: DIDResolver): this {
    this.didResolver = didResolver;
    return this;
  }

  addTrustedRootCertificate(pemBytes: Uint8Array): this {
    if (!this.trustedRootCertificates) {
      this.trustedRootCertificates = [];
    }

    this.trustedRootCertificates.push(pemBytes);
    return this;
  }

  /**
   * Adds a certificate trusted to anchor credential issuers, e.g. one from
   * {@link exportTrustList}. Unlike {@link addTrustedRootCertificate}, it may be an intermediate
   * or a listed signing certificate. Anchors are tried in order, after the trusted roots; the
   * first match's `sourceRef` and `role` are echoed in the issuer trust.
   *
   * Only issuing services, or anchors without a `serviceType`, anchor issuers; others only check
   * status lists, so pass an exported anchor's `serviceType` along.
   *
   * @param {TrustAnchor} anchor - the PEM, with optional `sourceRef`, `role` and `serviceType`.
   */
  addTrustAnchor(anchor: TrustAnchor): this {
    if (!this.trustAnchors) {
      this.trustAnchors = [];
    }

    this.trustAnchors.push(anchor);
    return this;
  }

  /**
   * Sets what an untrusted credential issuer does to a verification.
   *
   * - `enforce` (default): an untrusted issuer fails the verification with `IssuerNotTrusted`.
   * - `report`: issuer trust is only reported in `issuerTrust`; other checks still fail.
   *
   * @param {"enforce" | "report"} mode - the issuer trust mode.
   */
  withIssuerTrustMode(mode: "enforce" | "report"): this {
    this.issuerTrustMode = mode;
    return this;
  }

  /**
   * Sets which credential types are PIDs, QEAAs and PuB-EAAs, in addition to the EUDI PID types.
   * A credential is trusted only under anchors whose `role` fits its category (`pid_provider`,
   * `qeaa_provider`, `pub_eaa_provider`, `eaa_provider`); anchors without a role fit every
   * category unless {@link withRolelessAnchors} says otherwise.
   *
   * A trailing `*` matches by prefix. Unlisted credentials fall back to their `category` claim
   * (`urn:etsi:esi:eaa:eu:qualified`, `urn:etsi:esi:eaa:eu:pub`), then to EAA; request that claim
   * when relying on it.
   *
   * @param {CredentialClassification} classification - the credential types of each category.
   */
  withCredentialClassification(classification: CredentialClassification): this {
    this.credentialClassification = classification;
    return this;
  }

  /**
   * Sets which categories anchors without a role (e.g. trusted root certificates) may anchor.
   *
   * - `all_categories` (default): every category.
   * - `eaa_only`: only EAAs; other categories need an anchor with a matching role.
   *
   * @param {"all_categories" | "eaa_only"} scope - the categories role-less anchors may anchor.
   */
  withRolelessAnchors(scope: "all_categories" | "eaa_only"): this {
    this.rolelessAnchors = scope;
    return this;
  }

  /**
   * Sets the X.509 certificate chain emitted in the `x5c` header of the signed
   * Authorization Request Object.
   *
   * Required when the verifier's client id has an X.509 prefix; unused with any
   * other prefix. The leaf certificate must derive the configured client id —
   * its Subject Alternative Name for `x509_san_dns:<dns-name>`, its hash for
   * `x509_hash:<hash>` — and must certify the signing key of `keyMetadata`,
   * since the wallet checks the request signature against it. Both are enforced
   * when the request is built.
   *
   * @param {Uint8Array} pemBytes - a PEM-encoded, leaf-first certificate chain.
   */
  withX509CertificateChain(pemBytes: Uint8Array): this {
    this.x509CertificateChain = pemBytes;
    return this;
  }

  async build(): Promise<OID4VPVerifier> {
    const inner = await buildVpVerifier(
      contextEnsuredKms(this.kms),
      contextEnsuredNonceHandler(this.nonceHandler),
      this.keyMetadata,
      this.clientId,
      this.clientMetadata,
      this.httpClient,
      this.didResolver,
      this.trustedRootCertificates,
      this.x509CertificateChain,
      this.trustAnchors,
      this.issuerTrustMode,
      this.credentialClassification,
      this.rolelessAnchors,
    );
    return new OID4VPVerifier(inner);
  }
}
