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

            if has_key(&variant.fields, "location") {
                metadata.extend(quote! {
                    #name::#variant_ident { location, .. } => {
                        write!(fmt, " at: {}", location)?;
                    },
                });
            }
        }
    }

    let generated_code = quote! {
        impl std::fmt::Debug for #name {
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
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
