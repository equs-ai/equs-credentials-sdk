import {Dcql} from "./dcql";
import {PresentationDefinition} from "./presentation-definition";


/**
 * Currently we have to support both dcql and presentation definition protocols.
 * Later presentation definition will be deprecated. Until then ResolvedPresentationQuery
 * describes the used credential fetching protocol. Either dcql or presentation definition.
 */
export interface ResolvedPresentationQuery {
    presentation_definition?: PresentationDefinition,
    dcql_query?: Dcql
}