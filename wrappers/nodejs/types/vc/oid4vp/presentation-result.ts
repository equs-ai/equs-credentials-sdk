import { AuthorizationResponse as ASDKAuthResponse } from "../";
import { PresentationResultType } from "../../../";

type AuthorizationResponse = {
  type: PresentationResultType.AuthorizationResponse;
  value: ASDKAuthResponse;
};
type RedirectUri = {
  type: PresentationResultType.RedirectUri;
  value: string;
};
type Presented = {
  type: PresentationResultType.Presented;
};

export type PresentationResult = AuthorizationResponse | RedirectUri | Presented;
