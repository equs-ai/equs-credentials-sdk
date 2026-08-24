package org.equs.sdk.demo

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.equs.sdk.AuthCodeCallback
import com.equs.sdk.AuthorizationRequest
import com.equs.sdk.AuthorizationResponseMetadata
import com.equs.sdk.Credential
import com.equs.sdk.CredentialResultEnum
import com.equs.sdk.DidAndKeyMetadata
import com.equs.sdk.IdTokenMetadata
import com.equs.sdk.InMemKms
import com.equs.sdk.InMemVault
import com.equs.sdk.IssuerDiscoveryEnum
import com.equs.sdk.NonceHandler
import com.equs.sdk.NonceHandlerImpl
import com.equs.sdk.Oid4vciHolder
import com.equs.sdk.Oid4vciHolderBuilder
import com.equs.sdk.Oid4vpHolder
import com.equs.sdk.Oid4vpHolderBuilder
import com.equs.sdk.ProofOfPossessionMetadataBuilder
import com.equs.sdk.ProofOfPossessionNotBefore
import com.equs.sdk.ReqwestHttpClient
import com.equs.sdk.createDidAndKeyMetadata
import com.equs.sdk.resolveMetadata
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

const val CLIENT_ID = "wallet-dev"
const val SCOPE = "SD_JWT_cred_scope"
const val SD_JWT_CRED_DEF = "SD_JWT_cred_1"
const val ISSUER_URL = "http://localhost:8088"
const val VP_REQUEST_URI = "http://localhost:8098/request_uri/dcql"

class DemoViewModel : ViewModel() {
    private lateinit var holderVc: Oid4vciHolder
    private lateinit var holderVp: Oid4vpHolder
    private lateinit var didAndKeyMetadata: DidAndKeyMetadata
    private var token: String? = null

    private val authChannel = Channel<String>()
    val authRequest = authChannel.receiveAsFlow()

    private val credChannel = Channel<Credential>()
    val credential = credChannel.receiveAsFlow()

    private val presentationChannel = Channel<AuthorizationRequest>()
    val presentationRequest = presentationChannel.receiveAsFlow()

    fun submitCode(url: String, code: String) {
        viewModelScope.launch {
            pendingResponses[url]?.complete(code)
            pendingResponses.remove(url)
        }
    }

    init {
        viewModelScope.launch {
            val (holderVc_, holderVp_, didAndKeyMetadata_) = initialize()
            holderVc = holderVc_
            holderVp = holderVp_
            didAndKeyMetadata = didAndKeyMetadata_
        }
    }

    private val pendingResponses = mutableMapOf<String, CompletableDeferred<String>>()

    private val authCodeCallback = object : AuthCodeCallback {
        override suspend fun authenticate(url: String): String {
            val response = CompletableDeferred<String>()
            pendingResponses[url] = response
            authChannel.send(url)

            return response.await()
        }
    }

    fun startAuthentication() {
        viewModelScope.launch {
            token = holderVc.authzCodeFlowWithScope(SCOPE, authCodeCallback).accessToken
        }
    }

    fun startCredentialRequest() {
        token?.let {
            viewModelScope.launch {
                val credentialResult = requestAndStoreCredential(it, SD_JWT_CRED_DEF)
                credChannel.send(credentialResult)
            }
        }
    }

    private suspend fun requestAndStoreCredential(token: String, credDefId: String): Credential {
        val response = holderVc.requestCredential(
            token,
            credDefId,
            arrayListOf(didAndKeyMetadata.keyMetadata)
        )

        val credential = (response.data as CredentialResultEnum.Immediate).credentials.first()

        val metadata = resolveMetadata(credential, didAndKeyMetadata.keyMetadata)
        holderVc.storeCredential(credential, metadata)

        return credential
    }

    fun starPresentation(url: String) {
        viewModelScope.launch {
            val authRequest = holderVp.getAuthorizationRequest(url)
            presentationChannel.send(authRequest)

            val idTokenMetadata = IdTokenMetadata(didAndKeyMetadata.keyMetadata, 5)

            holderVp.presentCredentialsAuto(
                authRequest,
                AuthorizationResponseMetadata(null, idTokenMetadata)
            )
        }
    }

    private suspend fun initialize(): Triple<Oid4vciHolder, Oid4vpHolder, DidAndKeyMetadata> {
        val kms = InMemKms()
        val vault = InMemVault()
        val holderVp = Oid4vpHolderBuilder(
            kms, vault, CLIENT_ID,
            httpClient = ReqwestHttpClient.insecure(),
            nonceHandler = null
        ).build()
        val holderVci = Oid4vciHolderBuilder(
            kms,
            vault,
            CLIENT_ID,
            IssuerDiscoveryEnum.Url(ISSUER_URL),
            ReqwestHttpClient.insecure(),
            ProofOfPossessionMetadataBuilder()
                .withNotBefore(ProofOfPossessionNotBefore.Leeway(300))
                .withLifetime(300)
                .build(),
            null
        )
            .build()
        val didAndKeyMetadata = createDidAndKeyMetadata(kms)

        return Triple(holderVci, holderVp, didAndKeyMetadata)
    }
}
