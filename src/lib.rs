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

extern crate cbor;
extern crate routing;
extern crate sodiumoxide;
extern crate maidsafe_client;
extern crate rustc_serialize;

pub enum DnsError {
    /// Errors from Maidsafe-Client
    ClientError(::maidsafe_client::errors::ClientError),
    /// Dns record already exists
    DnsNameAlreadyRegistered,
    /// Dns record not found
    DnsRecordNotFound,
    /// Service already exists
    ServiceAlreadyExists,
    /// Service not found,
    ServiceNotFound,
    /// Unexpected, probably due to logical error
    Unexpected,
}

impl From<::maidsafe_client::errors::ClientError> for DnsError {
    fn from(error: ::maidsafe_client::errors::ClientError) -> DnsError {
        DnsError::ClientError(error)
    }
}

#[derive(Clone)] // TODO , Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfiguation {
    long_name         : String,
    encryption_keypair: (::sodiumoxide::crypto::box_::PublicKey,
                         ::sodiumoxide::crypto::box_::SecretKey),

}

impl ::rustc_serialize::Encodable for DnsConfiguation {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let encryption_keypair_vec = ((self.encryption_keypair.0).0.iter().map(|a| *a).collect::<Vec<u8>>(),
                                      (self.encryption_keypair.1).0.iter().map(|a| *a).collect::<Vec<u8>>());

        ::cbor::CborTagEncode::new(100_001, &(&self.long_name,
                                              encryption_keypair_vec)).encode(e)
    }
}

impl ::rustc_serialize::Decodable for DnsConfiguation {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let _ = try!(d.read_u64());

        let (long_name,
             encryption_keypair_vec):
            (String,
             (Vec<u8>, Vec<u8>)) = try!(::rustc_serialize::Decodable::decode(d));

        let mut encryption_keypair_arr = ([0u8; ::sodiumoxide::crypto::box_::PUBLICKEYBYTES],
                                          [0u8; ::sodiumoxide::crypto::box_::SECRETKEYBYTES]);

        for it in encryption_keypair_vec.0.iter().enumerate() {
            encryption_keypair_arr.0[it.0] = *it.1;
        }
        for it in encryption_keypair_vec.1.iter().enumerate() {
            encryption_keypair_arr.1[it.0] = *it.1;
        }

        Ok(DnsConfiguation {
            long_name         : long_name,
            encryption_keypair: (::sodiumoxide::crypto::box_::PublicKey(encryption_keypair_arr.0),
                                 ::sodiumoxide::crypto::box_::SecretKey(encryption_keypair_arr.1)),
        })
    }
}

/// The DNS structure
//#[derive(Clone, Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct Dns {
    long_name     : String,
    encryption_key: ::sodiumoxide::crypto::box_::PublicKey,
    services      : ::std::collections::HashMap<String, (u64, ::routing::NameType)>,
}

impl ::rustc_serialize::Encodable for Dns {
    fn encode<E: ::rustc_serialize::Encoder>(&self, e: &mut E) -> Result<(), E::Error> {
        let encryption_key_vec = self.encryption_key.0.iter().map(|a| *a).collect::<Vec<u8>>();

        ::cbor::CborTagEncode::new(100_001, &(&self.long_name,
                                              encryption_key_vec,
                                              &self.services)).encode(e)
    }
}

impl ::rustc_serialize::Decodable for Dns {
    fn decode<D: ::rustc_serialize::Decoder>(d: &mut D) -> Result<Self, D::Error> {
        let _ = try!(d.read_u64());

        let (long_name,
             encryption_key_vec,
             services):
            (String,
             Vec<u8>,
             ::std::collections::HashMap<String, (u64, ::routing::NameType)>) = try!(::rustc_serialize::Decodable::decode(d));

        let mut encryption_key_arr = [0u8; ::sodiumoxide::crypto::box_::PUBLICKEYBYTES];

        for it in encryption_key_vec.iter().enumerate() {
            encryption_key_arr[it.0] = *it.1;
        }

        Ok(::Dns {
            long_name     : long_name,
            encryption_key: ::sodiumoxide::crypto::box_::PublicKey(encryption_key_arr),
            services      : services,
        })
    }
}

struct DnsOperations {
    client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>,
}

impl DnsOperations {
    pub fn new(client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>) -> DnsOperations {
        DnsOperations {
            client: client,
        }
    }

    pub fn register_dns(&mut self,
                        long_name                      : String,
                        public_messaging_encryption_key: &::sodiumoxide::crypto::box_::PublicKey,
                        secret_messaging_encryption_key: &::sodiumoxide::crypto::box_::SecretKey,
                        services                       : &Vec<(String, (u64, ::routing::NameType))>,
                        owners                         : Vec<::sodiumoxide::crypto::sign::PublicKey>,
                        private_signing_key            : &::sodiumoxide::crypto::sign::SecretKey,
                        data_encryption_keys           : Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                 &::sodiumoxide::crypto::box_::SecretKey,
                                                                 &::sodiumoxide::crypto::box_::Nonce)>) -> Result<::maidsafe_client::client::StructuredData, ::DnsError> {
        let mut saved_configs = try!(self.get_dns_configuaration_data());
        if saved_configs.iter().any(|config| config.long_name == long_name) {
            Err(::DnsError::DnsNameAlreadyRegistered)
        } else {
            let identifier = ::routing::NameType::new(::sodiumoxide::crypto::hash::sha512::hash(long_name.as_bytes()).0);

            let dns_record = Dns {
                long_name: long_name.clone(),
                encryption_key: public_messaging_encryption_key.clone(),
                services: services.iter().map(|a| a.clone()).collect(),
            };

            saved_configs.push(DnsConfiguation {
                long_name: long_name,
                encryption_keypair: (public_messaging_encryption_key.clone(),
                                     secret_messaging_encryption_key.clone())

            });
            try!(self.write_dns_configuaration_data(saved_configs));

            Ok(try!(::maidsafe_client::structured_data_operations::unversioned::create(self.client.clone(),
                                                                                       5, // TODO
                                                                                       identifier,
                                                                                       0,
                                                                                       try!(::maidsafe_client::utility::serialise(&dns_record)),
                                                                                       owners,
                                                                                       vec![],
                                                                                       private_signing_key,
                                                                                       data_encryption_keys)))
        }
    }

    pub fn get_all_registered_names(&mut self) -> Result<Vec<String>, ::DnsError> {
        Ok(try!(self.get_dns_configuaration_data()).iter().map(|a| a.long_name.clone()).collect())
    }

    pub fn get_messaging_encryption_keys(&mut self, long_name: &String) -> Result<(::sodiumoxide::crypto::box_::PublicKey,
                                                                                   ::sodiumoxide::crypto::box_::SecretKey), ::DnsError> {
        let config_vec = try!(self.get_dns_configuaration_data());
        let dns_record = try!(config_vec.iter().find(|config| config.long_name == *long_name).ok_or(::DnsError::DnsRecordNotFound));
        Ok(dns_record.encryption_keypair.clone())
    }

    pub fn get_all_services(&mut self,
                            long_name           : &String,
                            data_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                          &::sodiumoxide::crypto::box_::SecretKey,
                                                          &::sodiumoxide::crypto::box_::Nonce)>) -> Result<Vec<String>, ::DnsError> {
        let (_, dns_record) = try!(self.get_dns_record_and_housing_sturctured_data(long_name, data_decryption_keys));
        Ok(dns_record.services.keys().map(|a| a.clone()).collect())
    }

    pub fn get_service_home_directory_key(&mut self,
                                          long_name           : &String,
                                          service_name        : &String,
                                          data_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                        &::sodiumoxide::crypto::box_::SecretKey,
                                                                        &::sodiumoxide::crypto::box_::Nonce)>) -> Result<(u64, ::routing::NameType), ::DnsError> {
        let (_, dns_record) = try!(self.get_dns_record_and_housing_sturctured_data(long_name, data_decryption_keys));
        Ok(try!(dns_record.services.get(service_name).ok_or(::DnsError::ServiceNotFound)).clone())
    }

    pub fn add_service(&mut self,
                       long_name                      : &String,
                       new_service                    : (String, (u64, ::routing::NameType)),
                       private_signing_key            : &::sodiumoxide::crypto::sign::SecretKey,
                       data_encryption_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                &::sodiumoxide::crypto::box_::SecretKey,
                                                                &::sodiumoxide::crypto::box_::Nonce)>) -> Result<::maidsafe_client::client::StructuredData, ::DnsError> {
        Ok(try!(self.add_remove_service_impl(long_name, (&new_service.0, Some(new_service.1)), private_signing_key, data_encryption_decryption_keys)))
    }

    pub fn remove_service(&mut self,
                          long_name                      : &String,
                          service_to_remove              : &String,
                          private_signing_key            : &::sodiumoxide::crypto::sign::SecretKey,
                          data_encryption_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                   &::sodiumoxide::crypto::box_::SecretKey,
                                                                   &::sodiumoxide::crypto::box_::Nonce)>) -> Result<::maidsafe_client::client::StructuredData, ::DnsError> {
        Ok(try!(self.add_remove_service_impl(long_name, (service_to_remove, None), private_signing_key, data_encryption_decryption_keys)))
    }

    fn add_remove_service_impl(&mut self,
                               long_name                      : &String,
                               service                        : (&String, Option<(u64, ::routing::NameType)>),
                               private_signing_key            : &::sodiumoxide::crypto::sign::SecretKey,
                               data_encryption_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                        &::sodiumoxide::crypto::box_::SecretKey,
                                                                        &::sodiumoxide::crypto::box_::Nonce)>) -> Result<::maidsafe_client::client::StructuredData, ::DnsError> {
        let is_add_service = service.1.is_some();

        let mut saved_configs = try!(self.get_dns_configuaration_data());
        if saved_configs.iter().any(|config| config.long_name == *long_name) {
            let (prev_struct_data, mut dns_record) = try!(self.get_dns_record_and_housing_sturctured_data(long_name,
                                                                                                          data_encryption_decryption_keys));

            if !is_add_service && !dns_record.services.contains_key(service.0) {
                Err(::DnsError::ServiceNotFound)
            } else if is_add_service && dns_record.services.contains_key(service.0) {
                Err(::DnsError::ServiceAlreadyExists)
            } else {
                if is_add_service {
                    let _ = dns_record.services.insert(service.0.clone(), try!(service.1.ok_or(::DnsError::Unexpected)));
                } else {
                    let _ = dns_record.services.remove(service.0);
                }

                let identifier = ::routing::NameType::new(::sodiumoxide::crypto::hash::sha512::hash(long_name.as_bytes()).0);

                Ok(try!(::maidsafe_client::structured_data_operations::unversioned::create(self.client.clone(),
                                                                                           5, // TODO
                                                                                           identifier,
                                                                                           prev_struct_data.get_version() + 1,
                                                                                           try!(::maidsafe_client::utility::serialise(&dns_record)),
                                                                                           prev_struct_data.get_owners().clone(),
                                                                                           prev_struct_data.get_previous_owners().clone(),
                                                                                           private_signing_key,
                                                                                           data_encryption_decryption_keys)))
            }
        } else {
            Err(::DnsError::DnsRecordNotFound)
        }
    }

    fn get_dns_record_and_housing_sturctured_data(&mut self,
                                                  long_name           : &String,
                                                  data_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                                &::sodiumoxide::crypto::box_::SecretKey,
                                                                                &::sodiumoxide::crypto::box_::Nonce)>) -> Result<(::maidsafe_client::client::StructuredData,
                                                                                                                                  Dns), ::DnsError> {
        let struct_data = try!(self.get_housing_structured_data(long_name, data_decryption_keys));
        let dns_record = try!(::maidsafe_client::utility::deserialise(&try!(::maidsafe_client::structured_data_operations::unversioned::get_data(self.client.clone(),
                                                                                                                                                 &struct_data,
                                                                                                                                                 data_decryption_keys))));
        Ok((struct_data, dns_record))
    }

    fn get_housing_structured_data(&mut self,
                                   long_name           : &String,
                                   data_decryption_keys: Option<(&::sodiumoxide::crypto::box_::PublicKey,
                                                                 &::sodiumoxide::crypto::box_::SecretKey,
                                                                 &::sodiumoxide::crypto::box_::Nonce)>) -> Result<::maidsafe_client::client::StructuredData, ::DnsError> {
        let identifier = ::routing::NameType::new(::sodiumoxide::crypto::hash::sha512::hash(long_name.as_bytes()).0);
        let location = ::maidsafe_client::client::StructuredData::compute_name(5, &identifier); // TODO 5
        let mut response_getter = try!(self.client.lock().unwrap().get(location, ::maidsafe_client::client::DataRequest::StructuredData(5)));
        if let ::maidsafe_client::client::Data::StructuredData(struct_data) = try!(response_getter.get()) { // TODO 5
            Ok(struct_data)
        } else {
            Err(::DnsError::ClientError(::maidsafe_client::errors::ClientError::ReceivedUnexpectedData))
        }
    }

    fn get_dns_configuaration_data(&mut self) -> Result<Vec<DnsConfiguation>, ::DnsError> {
        Ok(vec![])
    }

    fn write_dns_configuaration_data(&mut self, config: Vec<DnsConfiguation>) -> Result<(), ::DnsError> {
        Ok(())
    }
}
