import {PresentationQuery} from "./authorization-request";

export interface PresentationSession {
    nonce: string
    presentation_query: PresentationQuery
    authorizationRequestJwt?: string
}