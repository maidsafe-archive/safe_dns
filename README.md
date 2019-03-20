# ***This repository is no longer maintained***
# It has been moved to the maidsafe-archive organisation for reference only
#
#
#
#
# safe_dns

[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/safe_dns/blob/master/COPYING)

**Primary Maintainer:**     Krishna Kumar (krishna.kumar@maidsafe.net)

**Secondary Maintainer:**   Spandan Sharma (spandan.sharma@maidsafe.net)

|Crate|Linux/OS X|Windows|Coverage|Issues|
|:---:|:--------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/safe_dns)](https://crates.io/crates/safe_dns)|[![Build Status](https://travis-ci.org/maidsafe/safe_dns.svg?branch=master)](https://travis-ci.org/maidsafe/safe_dns)|[![Build status](https://ci.appveyor.com/api/projects/status/eig27xveg95e6ct6/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/safe-dns/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/safe_dns/badge.svg)](https://coveralls.io/r/maidsafe/safe_dns)|[![Stories in Ready](https://badge.waffle.io/maidsafe/safe_dns.png?label=ready&title=Ready)](https://waffle.io/maidsafe/safe_dns)|

| [API Documentation - master branch](http://maidsafe.net/safe_dns/master) | [SAFE Network System Documentation](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [SAFE Network Forum](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

## Prerequisite

[libsodium](https://github.com/jedisct1/libsodium) is a native dependency, and can be installed by following the instructions [for Windows](https://github.com/maidsafe/QA/blob/master/Documentation/Install%20libsodium%20for%20Windows.md) or [for OS X and Linux](https://github.com/maidsafe/QA/blob/master/Documentation/Install%20libsodium%20for%20OS%20X%20or%20Linux.md).

## Build Instructions
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
