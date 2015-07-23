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

#[derive(Clone)] // TODO , Debug, Eq, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DnsConfiguation {
    pub long_name         : String,
    pub encryption_keypair: (::sodiumoxide::crypto::box_::PublicKey,
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

pub fn get_dns_configuaration_data(_client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>) -> Result<Vec<DnsConfiguation>, ::errors::DnsError> {
    Ok(vec![])
}

pub fn write_dns_configuaration_data(_client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>,
                                     _config: Vec<DnsConfiguation>) -> Result<(), ::errors::DnsError> {
    Ok(())
}
