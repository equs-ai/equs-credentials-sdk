import {PresentationDefinition} from "./presentation-definition";
import {ClientMetadata} from "./client-metadata";
import {Dcql} from "./dcql";
import {ResolvedPresentationQuery} from "./resolved-presentation-query";


type InternalRustAuthorizationRequest = {
    client_id: string,
    client_metadata: ClientMetadata,
    resolved_presentation_query: ResolvedPresentationQuery,
    nonce: string,
    response_type: string,
    response_mode: string,
    response_uri: string,
    state?: string,
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

    private get dcql(): InternalRustAuthorizationRequest {
        return {
            client_id: this.authRequest.client_id,
            nonce: this.authRequest.nonce,
            state: this.authRequest.state,
            response_mode: this.authRequest.response_mode,
            response_uri: this.authRequest.response_uri,
            response_type: this.authRequest.response_type,
            client_metadata: this.authRequest.client_metadata,
            resolved_presentation_query: {
                dcql_query: this.authRequest.dcql_query,
            },
        };
    }

    private get pd(): InternalRustAuthorizationRequest {
        return {
            client_id: this.authRequest.client_id,
            nonce: this.authRequest.nonce,
            state: this.authRequest.state,
            response_mode: this.authRequest.response_mode,
            response_uri: this.authRequest.response_uri,
            response_type: this.authRequest.response_type,
            client_metadata: this.authRequest.client_metadata,
            resolved_presentation_query: {
                presentation_definition: this.authRequest.presentation_definition,
            },
        };
    }

    toRustObject(): InternalRustAuthorizationRequest {
        return this.isDCQL(this.authRequest) ? this.dcql : this.pd;
    }

    getAuthRequest(): CommonAuthorizationRequest {
        return this.authRequest;
    }

    private isDCQL(
        authRequest: CommonAuthorizationRequest,
    ): authRequest is AuthorizationRequestWithoutRPQ & ResolvedPresentationQueryWithDCQL {
        return Object.hasOwn(authRequest, "dcql_query");
    }
}
