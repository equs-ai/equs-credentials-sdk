interface DescriptorMap {
	id: string;
	format: string;
	path: string;
	path_nested?: DescriptorMap;
}

export interface PresentationSubmission {
	id: string;
	definition_id: string;
	descriptor_map: Array<DescriptorMap>;
}
