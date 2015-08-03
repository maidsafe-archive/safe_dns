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

/// Safe-Dns specific errors
pub enum DnsError {
    /// Errors from Safe-Client
    ClientError(::safe_client::errors::ClientError),
    /// Errors from Safe-Nfs
    NfsError(::safe_nfs::errors::NfsError),
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

impl From<::safe_client::errors::ClientError> for DnsError {
    fn from(error: ::safe_client::errors::ClientError) -> DnsError {
        DnsError::ClientError(error)
    }
}

impl From<::safe_nfs::errors::NfsError> for DnsError {
    fn from(error: ::safe_nfs::errors::NfsError) -> DnsError {
        match error {
            ::safe_nfs::errors::NfsError::ClientError(error) => DnsError::ClientError(error),
            _ => DnsError::NfsError(error),
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
            DnsError::ClientError(ref error)           => write!(f, "DnsError::ClientError -> {:?}", error),
            DnsError::NfsError(ref error)              => write!(f, "DnsError::NfsError -> {:?}", error),
            DnsError::DnsNameAlreadyRegistered         => write!(f, "DnsError::DnsNameAlreadyRegistered"),
            DnsError::DnsRecordNotFound                => write!(f, "DnsError::DnsRecordNotFound"),
            DnsError::ServiceAlreadyExists             => write!(f, "DnsError::ServiceAlreadyExists"),
            DnsError::ServiceNotFound                  => write!(f, "DnsError::ServiceNotFound"),
            DnsError::DnsConfigFileNotFoundOrCorrupted => write!(f, "DnsError::DnsConfigFileNotFoundOrCorrupted"),
            DnsError::Unexpected(ref error)            => write!(f, "DnsError::Unexpected::{{{:?}}}", error),
        }
    }
}
