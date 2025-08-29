pub trait IntoNapiError {
    fn into_napi_error(self) -> napi::Error;
}
