use anyhow::{bail, Error};
use oid4vp::{
    core::authorization_request::parameters::PresentationDefinition as PresentationDefinitionParameter,
    presentation_exchange::{InputDescriptor, PresentationDefinition},
};
use serde_json::Value as Json;
use tracing::{instrument, Level};
use uuid::Uuid;

pub use oid4vp::core::profile::PresentationBuilder;

#[derive(Debug)]
pub struct DefaultPresentationBuilder(PresentationDefinition);

// TODO: Improve the Presentation Builder to make it easier to create presentation definition
impl DefaultPresentationBuilder {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn new(id: String) -> DefaultPresentationBuilder {
        DefaultPresentationBuilder(PresentationDefinition {
            id,
            input_descriptors: vec![],
            name: None,
            purpose: None,
            format: None,
        })
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn from(presentation_definition: PresentationDefinition) -> DefaultPresentationBuilder {
        DefaultPresentationBuilder(presentation_definition)
    }

    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(),
    )]
    pub fn with_input_descriptor(mut self, input_descriptor: &InputDescriptor) -> Self {
        self.0.input_descriptors.push(input_descriptor.clone());
        self
    }

    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(),
    )]
    pub fn with_name(mut self, name: &str) -> Self {
        self.0.name = Some(name.to_string());
        self
    }

    #[instrument(
        level = Level::TRACE,
        skip(self)
        ret(),
    )]
    pub fn with_format(mut self, format: Json) -> Self {
        self.0.format = Some(format);
        self
    }
}

impl Default for DefaultPresentationBuilder {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn default() -> Self {
        DefaultPresentationBuilder::new(Uuid::new_v4().to_string())
    }
}

impl PresentationBuilder for DefaultPresentationBuilder {
    #[instrument(
        level = Level::TRACE,
        skip(self)
        err(),
        ret(),
    )]
    fn build(self) -> Result<PresentationDefinitionParameter, Error> {
        if self.0.input_descriptors.is_empty() {
            bail!("At least one input descriptor should be provided")
        }

        PresentationDefinitionParameter::try_from(self.0)
    }
}
