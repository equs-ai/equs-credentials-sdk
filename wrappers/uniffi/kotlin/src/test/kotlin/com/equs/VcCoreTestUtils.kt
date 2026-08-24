package com.equs

import com.equs.sdk.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

object VcCoreFixtures {
    const val NONCE = "KB50VOm9I-kPLT9mAACV8g"
    const val VERIFIER_ID = "Verifier-id"
    const val SCOPE = "SD_JWT_cred_sample"
    const val ISSUER_ID = "https://issuer-backend.com"
    const val STATUS_LIST_ID = "test_status_list"
    const val STATUS_LIST_URL = "http://localhost:9001/status_list"
    const val VCT = "https://credentials.example.com/identity_credential"

    val claims: String = buildJsonObject {
        put("name", "John")
        put("surname", "Doe")
        put("address", "221B Baker Street")
        put("date", "09/09/1989")
    }.toString()

    val credStatusInfo: CredentialStatusInfo =
        CredentialStatusInfo.TokenStatusList(idx = 1u, uri = STATUS_LIST_URL)

    fun statusIssuerMetadata(keyMetadata: KeyMetadata): StatusIssuerMetadata =
        StatusIssuerMetadata(
            issuerId = "test",
            supportedStatusLists =
                listOf(
                    StatusListDefinition(
                        id = STATUS_LIST_ID,
                        format =
                            StatusListFormat.StatusListTokenJwt(
                                SlMetadata(
                                    statusListUrl = STATUS_LIST_URL,
                                    statusesNr = 32u,
                                    statusSize = 2u.toUByte(),
                                ),
                            ),
                        keyMetadata = keyMetadata,
                    ),
                ),
        )

    fun issuerMetadata(keyMetadata: KeyMetadata): IssuerMetadata {
        return IssuerMetadata(
            issuerId = ISSUER_ID,
            credDefs =
                listOf(
                    CredentialDefinition(
                        credDefId = SCOPE,
                        format = VcFormat.SD_JWT_VC,
                        claims = emptyMap(),
                        supportedProofs = listOf(SupportedProofEntry(PopFormat.JWT, listOf(Alg.ES256))),
                        supportedSigningAlgs = listOf(Alg.ES256, Alg.ED_DSA),
                        display = null,
                        protocolData =
                            CredentialDefinitionData.SdJwt(
                                vct = VCT,
                                disclosures = listOf("\$.name", "\$.surname"),
                                lifetime = 600L,
                            ),
                        keyMetadata = keyMetadata,
                    ),
                ),
            protocolData = null,
        )
    }

    fun holderMetadata(): HolderMetadata =
        HolderMetadata(
            clientId = "wallet-dev",
            pop =
                ProofOfPossessionMetadataBuilder()
                    .withLifetime(300L)
                    .build(),
        )

    fun presentationInput(): PresentationInput =
        PresentationInput(
            id = SCOPE,
            format = "dc+sd-jwt",
            restrictions =
                listOf(
                    PresentationRestriction(
                        fields = listOf("\$.vct"),
                        value = PresentationRestrictionValue.Const(VCT),
                        optional = false,
                    ),
                    PresentationRestriction(
                        fields = listOf("\$.surname"),
                        value = null,
                        optional = false,
                    ),
                ),
        )

    fun emptyCredentialOffer(keyMetadata: KeyMetadata): CredentialOffer {
        return CredentialOffer(
            credOfferId = null,
            issuerId = ISSUER_ID,
            credDefId = SCOPE,
            content =
                CredentialOfferContent.CredDef(
                    CredentialDefinition(
                        credDefId = SCOPE,
                        format = VcFormat.SD_JWT_VC,
                        claims = emptyMap(),
                        supportedProofs = listOf(SupportedProofEntry(PopFormat.JWT, listOf(Alg.ES256))),
                        supportedSigningAlgs = listOf(Alg.ES256, Alg.ED_DSA),
                        display = null,
                        protocolData =
                            CredentialDefinitionData.SdJwt(
                                vct = VCT,
                                disclosures = listOf("\$.name", "\$.surname"),
                                lifetime = 600L,
                            ),
                        keyMetadata = keyMetadata,
                    ),
                ),
            protocolData = null,
        )
    }
}
