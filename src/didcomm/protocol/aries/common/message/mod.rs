pub mod status;
pub mod thread;

#[macro_export]
macro_rules! impl_didcomm_message_conversion {
    ($ty:ty) => {
        impl TryFrom<$crate::didcomm::core::envelope::Message> for $ty {
            type Error = ::serde_json::Error;

            fn try_from(
                value: $crate::didcomm::core::envelope::Message,
            ) -> ::serde_json::Result<Self> {
                ::serde_json::to_value(value).and_then(|json| serde_json::from_value(json))
            }
        }

        impl TryFrom<$ty> for $crate::didcomm::core::envelope::Message {
            type Error = ::serde_json::Error;

            fn try_from(value: $ty) -> ::serde_json::Result<Self> {
                ::serde_json::to_value(value).and_then(|json| serde_json::from_value(json))
            }
        }
    };
}
