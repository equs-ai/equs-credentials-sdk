import {PresentationDefinition} from "./presentation-definition";
import {ClientMetadata} from "./client-metadata";
import {Dcql} from "./dcql";
import {TransactionDataItem} from "./transaction-data-item";


type InternalRustAuthorizationRequest = {
    client_id: string,
    client_metadata: ClientMetadata,
    resolved_presentation_query: PresentationQuery,
    nonce: string,
    response_type: string,
    response_mode: string,
    response_uri: string,
    state?: string,
    transaction_data?: Array<TransactionDataItem> | null | undefined,
}

type ResolvedPresentationQueryWithPD = {
    presentation_definition: PresentationDefinition;
    dcql_query?: never;
};
type ResolvedPresentationQueryWithDCQL = {
    dcql_query: Dcql;
    presentation_definition?: never;
};

export type PresentationQuery = ResolvedPresentationQueryWithPD | ResolvedPresentationQueryWithDCQL;

type AuthorizationRequestWithoutRPQ = Omit<InternalRustAuthorizationRequest, "resolved_presentation_query">;

export type CommonAuthorizationRequest =
    | (AuthorizationRequestWithoutRPQ & ResolvedPresentationQueryWithDCQL)
    | (AuthorizationRequestWithoutRPQ & ResolvedPresentationQueryWithPD);

export class AuthorizationRequest {
    private readonly authRequest: CommonAuthorizationRequest;

    constructor(params: CommonAuthorizationRequest) {
        this.authRequest = params;
    }

    get presentationQuery(): PresentationQuery {
        if (this.authRequest.dcql_query) return {
            dcql_query: this.authRequest.dcql_query,
        };
        if (this.authRequest.presentation_definition) return {
            presentation_definition: this.authRequest.presentation_definition,
        };
        throw new Error("Either dcql_query or presentation_definition must be provided");
    }

    toRustObject(): InternalRustAuthorizationRequest {

        return {
            client_id: this.authRequest.client_id,
            nonce: this.authRequest.nonce,
            state: this.authRequest.state,
            response_mode: this.authRequest.response_mode,
            response_uri: this.authRequest.response_uri,
            response_type: this.authRequest.response_type,
            client_metadata: this.authRequest.client_metadata,
            resolved_presentation_query: this.presentationQuery,
            transaction_data: this.authRequest.transaction_data,
        }
    }

    getAuthRequest(): CommonAuthorizationRequest {
        return this.authRequest;
    }
}
