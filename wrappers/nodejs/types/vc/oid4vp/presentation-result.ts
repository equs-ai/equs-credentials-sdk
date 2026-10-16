import { AuthorizationResponse as EqusSdkAuthResponse } from "../";
import { PresentationResultType } from "../../../";

type AuthorizationResponse = {
  type: PresentationResultType.AuthorizationResponse;
  value: EqusSdkAuthResponse;
};
type RedirectUri = {
  type: PresentationResultType.RedirectUri;
  value: string;
};
type Presented = {
  type: PresentationResultType.Presented;
};

export type PresentationResult = AuthorizationResponse | RedirectUri | Presented;
