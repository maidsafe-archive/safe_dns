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

/// Maidsafe-Dns specific errors
pub enum DnsError {
    /// Errors from Maidsafe-Client
    ClientError(::maidsafe_client::errors::ClientError),
    /// Dns record already exists
    DnsNameAlreadyRegistered,
    /// Dns record not found
    DnsRecordNotFound,
    /// Service already exists
    ServiceAlreadyExists,
    /// Service not found
    ServiceNotFound,
    /// Dns Configuration file not found or corrupted
    DnsConfigFileNotFoundOrCorrupted,
    /// Unexpected, probably due to logical error
    Unexpected(String),
}

impl From<::maidsafe_client::errors::ClientError> for DnsError {
    fn from(error: ::maidsafe_client::errors::ClientError) -> DnsError {
        DnsError::ClientError(error)
    }
}

// TODO change to NfsError
impl From<::maidsafe_nfs::errors::NFSError> for DnsError {
    fn from(error: ::maidsafe_nfs::errors::NFSError) -> DnsError {
        match error {
            ::maidsafe_nfs::errors::NFSError::ClientError(error) => DnsError::ClientError(error),
        }
    }
}

impl From<String> for DnsError {
    fn from(error: String) -> DnsError {
        DnsError::Unexpected(error)
    }
}

impl ::std::fmt::Debug for DnsError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            DnsError::ClientError(ref error)           => writeln!(f, "DnsError::ClientError -> {:?}", error),
            DnsError::DnsNameAlreadyRegistered         => writeln!(f, "DnsError::DnsNameAlreadyRegistered"),
            DnsError::DnsRecordNotFound                => writeln!(f, "DnsError::DnsRecordNotFound"),
            DnsError::ServiceAlreadyExists             => writeln!(f, "DnsError::ServiceAlreadyExists"),
            DnsError::ServiceNotFound                  => writeln!(f, "DnsError::ServiceNotFound"),
            DnsError::DnsConfigFileNotFoundOrCorrupted => writeln!(f, "DnsError::DnsConfigFileNotFoundOrCorrupted"),
            DnsError::Unexpected(ref error)            => writeln!(f, "DnsError::Unexpected::{:?}", error),
        }
    }
}
