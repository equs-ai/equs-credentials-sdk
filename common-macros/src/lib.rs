use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

#[proc_macro_derive(DebugError)]
pub fn derive_debug(input: TokenStream) -> TokenStream {
    let ast: syn::DeriveInput = parse_macro_input!(input);

    let name = &ast.ident;

    let generated_code = quote! {
        impl Debug for #name {
            fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
                std::write!(fmt, "{}", self)?;

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
