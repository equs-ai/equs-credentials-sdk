import { CredentialFormats } from "./common";

interface DescriptorMap {
	id: string;
	format: CredentialFormats;
	path: string;
	path_nested?: DescriptorMap;
}

export interface PresentationSubmission {
	id: string;
	definition_id: string;
	descriptor_map: Array<DescriptorMap>;
}
