use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(Permissions)]
pub fn derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_fields = match input.data {
        syn::Data::Enum(x) => x.variants,
        _ => {
            return syn::Error::new_spanned(input, "expected enum")
                .to_compile_error()
                .into()
        }
    };

    let traits = build_traits(&enum_fields, &input.ident);

    let expanded = quote! {
        #traits
    };

    TokenStream::from(expanded)
}

fn build_traits(
    fields: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
    enum_ident: &proc_macro2::Ident,
) -> proc_macro2::TokenStream {
    let mut tts = Vec::new();

    for f in fields.iter() {
        let trait_name = syn::Ident::new(&format!("T{}", f.ident.clone()), f.ident.span());
        let struct_name = f.ident.clone();
        let enum_name = enum_ident.clone();
        tts.push(quote! {
            pub trait #trait_name {}
            pub struct #struct_name;
            impl #trait_name for #struct_name {}
            impl type_permissions::Dispatch<#enum_name> for #struct_name {
                fn dispatch() -> std::collections::HashSet<#enum_name> {
                    let mut set = std::collections::HashSet::new();
                    set.insert(#enum_name::#struct_name);
                    set
                }
            }
            impl type_permissions::Dispatch<#enum_name> for dyn #trait_name {
                fn dispatch() -> std::collections::HashSet<#enum_name> {
                    let mut set = std::collections::HashSet::new();
                    set.insert(#enum_name::#struct_name);
                    set
                }
            }
        });
    }

    quote! { #(#tts)* }
}
