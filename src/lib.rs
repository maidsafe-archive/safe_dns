// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![crate_name = "maidsafe_dns"]
#![crate_type = "lib"]
#![doc(html_logo_url = "http://maidsafe.net/img/Resources/branding/maidsafe_logo.fab2.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
              html_root_url = "http://dirvine.github.io/dirvine/maidsafe_dns/")]

///////////////////////////////////////////////////
//               LINT
///////////////////////////////////////////////////

#![forbid(bad_style, warnings)] 

#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints, unsafe_code,
unsigned_negation, unused, unused_allocation, unused_attributes, unused_comparisons,
unused_features, unused_parens, while_true)] 

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, variant_size_differences)]

///////////////////////////////////////////////////

#![allow(missing_docs, unused)] // TODO

//! #Maidsafe-Dns Library
//! [Project github page](https://github.com/maidsafe/maidsafe_dns)

extern crate routing;
extern crate sodiumoxide;
extern crate maidsafe_client;
//extern crate rustc_serialize;

//#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfiguation {
    long_name         : String,
    ownership_keypair : (::sodiumoxide::crypto::sign::PublicKey,
                        ::sodiumoxide::crypto::sign::SecretKey),
    encryption_keypair: (::sodiumoxide::crypto::box_::PublicKey,
                         ::sodiumoxide::crypto::box_::SecretKey),

}

/// The DNS structure
//#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Dns {
    long_name     : String,
    encryption_key: ::sodiumoxide::crypto::box_::PublicKey,
    services      : ::std::collections::HashMap<String, ::routing::NameType>,
}

pub fn register_dns(_long_name         : String,
                    _pub_encryption_key: ::sodiumoxide::crypto::box_::PublicKey) -> Result<(), ::maidsafe_client::errors::ClientError> {
    unimplemented!();
}

pub fn add_service(_long_name: &String, _new_service: &String) -> Result<(), ::maidsafe_client::errors::ClientError> {
    unimplemented!();
}

pub fn get_all_registered_names() -> Result<Vec<String>, ::maidsafe_client::errors::ClientError> {
    unimplemented!();
}

pub fn get_all_services(_long_name: &String) -> Result<Vec<String>, ::maidsafe_client::errors::ClientError> {
    unimplemented!();
}

pub fn get_service_home_directory_name(_long_name   : &String,
                                       _service_name: &String) -> Result<::routing::NameType, ::maidsafe_client::errors::ClientError> {
    unimplemented!();
}

//fn create_or_get_configuaration_file() -> Result<
