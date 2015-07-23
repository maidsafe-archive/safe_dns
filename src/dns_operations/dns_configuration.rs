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

const DNS_CONFIG_DIR_NAME: &'static str = "DnsReservedDirectory";
const DNS_CONFIG_FILE_NAME: &'static str = "DnsConfigurationFile";

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

pub fn initialise_dns_configuaration(client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>) -> Result<(), ::errors::DnsError> {
    let dir_listing = try!(::maidsafe_nfs::utility::get_configuration_directory_id(client.clone(), DNS_CONFIG_DIR_NAME.to_string()));
    let mut file_helper = ::maidsafe_nfs::helper::FileHelper::new(client.clone());
    match file_helper.create(DNS_CONFIG_FILE_NAME.to_string(), vec![], &dir_listing) {
        Ok(writer) => Ok(try!(writer.close())),
        Err(_)     => Ok(()), // TODO improve in nfs-crate
    }
}

pub fn get_dns_configuaration_data(client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>) -> Result<Vec<DnsConfiguation>, ::errors::DnsError> {
    let dir_listing = try!(::maidsafe_nfs::utility::get_configuration_directory_id(client.clone(), DNS_CONFIG_DIR_NAME.to_string()));
    let file = try!(dir_listing.get_files().iter().find(|file| file.get_name() == DNS_CONFIG_FILE_NAME).ok_or(::errors::DnsError::DnsConfigFileNotFoundOrCorrupted)).clone();
    let mut reader = ::maidsafe_nfs::io::reader::Reader::new(file, client);
    let size = reader.size();
    Ok(try!(::maidsafe_client::utility::deserialise(&try!(reader.read(0, size)))))
}

pub fn write_dns_configuaration_data(client: ::std::sync::Arc<::std::sync::Mutex<::maidsafe_client::client::Client>>,
                                     config: &Vec<DnsConfiguation>) -> Result<(), ::errors::DnsError> {
    let dir_listing = try!(::maidsafe_nfs::utility::get_configuration_directory_id(client.clone(), DNS_CONFIG_DIR_NAME.to_string()));
    let file = try!(dir_listing.get_files().iter().find(|file| file.get_name() == DNS_CONFIG_FILE_NAME).ok_or(::errors::DnsError::DnsConfigFileNotFoundOrCorrupted));
    let mut file_helper = ::maidsafe_nfs::helper::FileHelper::new(client.clone());
    let mut writer = try!(file_helper.update(file, &dir_listing, ::maidsafe_nfs::io::writer::Mode::Overwrite));
    writer.write(&try!(::maidsafe_client::utility::serialise(&config)), 0);
    Ok(try!(writer.close()))
}

#[cfg(test)]
mod test {
    //use super::*;
}
