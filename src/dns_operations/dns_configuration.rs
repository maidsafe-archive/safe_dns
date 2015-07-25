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

impl PartialEq for DnsConfiguation {
    fn eq(&self, other: &DnsConfiguation) -> bool {
        self.long_name == other.long_name &&
            self.encryption_keypair.0 .0.iter().chain(self.encryption_keypair.1 .0.iter()).zip(
                other.encryption_keypair.0 .0.iter().chain(other.encryption_keypair.1 .0.iter())).all(|a| a.0 == a.1)
    }
}

impl ::std::fmt::Debug for DnsConfiguation {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{:?}", self.long_name)
    }
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
    if size != 0 {
        Ok(try!(::maidsafe_client::utility::deserialise(&try!(reader.read(0, size)))))
    } else {
        Ok(vec![])
    }
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
    use super::*;

    #[test]
    fn read_write_dns_configuration_file() {
        let client = ::std::sync::Arc::new(::std::sync::Mutex::new(eval_result!(::maidsafe_client::utility::test_utils::get_client())));

        // Initialise Dns Configuration File
        eval_result!(initialise_dns_configuaration(client.clone()));

        // Get the Stored Configurations
        let mut config_vec = eval_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);

        let long_name = eval_result!(::maidsafe_client::utility::generate_random_string(10));

        // Put in the 1st record
        let mut keypair = ::sodiumoxide::crypto::box_::gen_keypair();
        let config_0 = DnsConfiguation {
            long_name         : long_name.clone(),
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec.push(config_0.clone());
        eval_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = eval_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert_eq!(config_vec[0], config_0);

        // Modify the content
        keypair = ::sodiumoxide::crypto::box_::gen_keypair();
        let config_1 = DnsConfiguation {
            long_name         : long_name,
            encryption_keypair: (keypair.0, keypair.1),
        };

        config_vec[0] = config_1.clone();
        eval_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = eval_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 1);

        assert!(config_vec[0] != config_0);
        assert_eq!(config_vec[0], config_1);

        // Delete Record
        config_vec.clear();
        eval_result!(write_dns_configuaration_data(client.clone(), &config_vec));

        // Get the Stored Configurations
        config_vec = eval_result!(get_dns_configuaration_data(client.clone()));
        assert_eq!(config_vec.len(), 0);
    }
}
