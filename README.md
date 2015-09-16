# safe_dns

[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/safe_dns/blob/master/COPYING)

**Primary Maintainer:**     Krishna Kumar (krishna.kumar@maidsafe.net)

**Secondary Maintainer:**   Spandan Sharma (spandan.sharma@maidsafe.net)

|Crate|Linux/OS X|Windows|Coverage|Issues|
|:---:|:--------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/safe_dns)](https://crates.io/crates/safe_dns)|[![Build Status](https://travis-ci.org/maidsafe/safe_dns.svg?branch=master)](https://travis-ci.org/maidsafe/safe_dns)|[![Build status](https://ci.appveyor.com/api/projects/status/eig27xveg95e6ct6/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/safe-dns/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/safe_dns/badge.svg)](https://coveralls.io/r/maidsafe/safe_dns)|[![Stories in Ready](https://badge.waffle.io/maidsafe/safe_dns.png?label=ready&title=Ready)](https://waffle.io/maidsafe/safe_dns)|

| [API Documentation - master branch](http://maidsafe.net/safe_dns/master/) | [SAFE Network System Documention](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

###Pre-requisite:
`libsodium` is a native dependency for [sodiumxoide](https://github.com/dnaq/sodiumoxide). Install sodium by following the instructions [here](https://github.com/maidsafe/QA/blob/master/Documentation/Install_libsodium.md).

###Build Instructions:
`safe_dns` depends on `safe_client` which can interface conditionally against either the routing crate or a mock used for local testing.

To use it with the Mock:
```
cargo build --features "use-mock-routing"
cargo test --features "use-mock-routing"
```

To interface it with actual routing (default):
```
cargo build
cargo test
```

## TODO

### [0.1.1]
- [ ] [MAID-1314](https://maidsafe.atlassian.net/browse/MAID-1314) Remove all unwraps
- [ ] [MAID-1315](https://maidsafe.atlassian.net/browse/MAID-1315) Remove unwanted errors and Unexpected should take an &str instead of String
- [ ] [MAID-1316](https://maidsafe.atlassian.net/browse/MAID-1316) Put debug statements
- [ ] [MAID-1317](https://maidsafe.atlassian.net/browse/MAID-1317) check for all muts (eg., response_getter etc) and validate if really required
- [ ] [MAID-1318](https://maidsafe.atlassian.net/browse/MAID-1318) Follow changes in NFS and Client
- [ ] [MAID-1319](https://maidsafe.atlassian.net/browse/MAID-1319) Address the TODO’s and make temporary fixes as permanent
- [ ] [MAID-1320](https://maidsafe.atlassian.net/browse/MAID-1320) Test cases for TODO's and temporary fixes as permanent
