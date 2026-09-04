use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(DebugError)]
pub fn derive_debug(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = parse_macro_input!(input);
    let name = &ast.ident;

    let mut metadata = quote! {};

    if let Data::Enum(data_enum) = &ast.data {
        for variant in &data_enum.variants {
            let variant_ident = &variant.ident;

            let location = has_key(&variant.fields, "location");
            let source = has_key(&variant.fields, "source");

            let pattern = match (location, source) {
                (true, true) => quote! { { location, source, .. } },
                (true, false) => quote! { { location, .. } },
                (false, true) => quote! { { source, .. } },
                (false, false) => continue,
            };

            let mut body = quote! {};

            if location {
                body.extend(quote! {
                    write!(fmt, " at: {}", location)?;
                });
            }

            if source {
                body.extend(quote! {
                    write!(fmt, "\n Cause: ")?;
                    return source.__debug_error_chain(fmt);
                });
            }

            metadata.extend(quote! {
                #name::#variant_ident #pattern => { #body },
            });
        }
    }

    let generated_code = quote! {
        impl #name {
            #[doc(hidden)]
            pub fn __debug_error_chain(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                trait DisplayChain {
                    fn __debug_error_chain(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result;
                }

                impl<T: ?Sized + snafu::AsErrorSource> DisplayChain for T {
                    fn __debug_error_chain(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                        let mut error = self.as_error_source();

                        write!(fmt, "{}", error)?;

                        while let Some(source) = error.source() {
                            write!(fmt, "\n Cause: {}", source)?;
                            error = source;
                        }

                        Ok(())
                    }
                }

                write!(fmt, "{}", self)?;

                match self {
                    #metadata
                    _ => {}
                }

                let mut error: &dyn std::error::Error = self;

                while let Some(source) = error.source() {
                    write!(fmt, "\n Cause: {}", source)?;
                    error = source;
                }

                Ok(())
            }
        }

        impl std::fmt::Debug for #name {
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.__debug_error_chain(fmt)
            }
        }
    };

    generated_code.into()
}

fn has_key(fields: &Fields, key: &str) -> bool {
    match fields {
        Fields::Named(fields_named) => fields_named
            .named
            .iter()
            .any(|f| f.ident.as_ref().map(|v| v == key).unwrap_or(false)),
        _ => false,
    }
}
