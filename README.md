# maidsafe_nfs

**Primary Maintainer:**     Spandan Sharma (spandan.sharma@maidsafe.net)

**Secondary Maintainer:**   Krishna Kumar (krishna.kumar@maidsafe.net)


| [API Documentation - master branch](http://maidsafe.net/maidsafe_nfs/master) | [SAFE Network System Documentation](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [Safe Community site](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

###Build Instructions:
Maidsafe-Client interfaces conditionally with either the actual routing crate or the Mock used for efficient local testing.

To use it with the Mock (default) do:
```
cargo build
cargo test
etc
```
##TODO (rust_3 sprint)
###Version 0.1.0
- [ ] [MAID-1240](https://maidsafe.atlassian.net/browse/MAID-1240) Create DNS mapping
- [ ] [MAID-1241](https://maidsafe.atlassian.net/browse/MAID-1241) Update DNS Mapping
- [ ] [MAID-1242](https://maidsafe.atlassian.net/browse/MAID-1242) Delete DNS Mapping
- [ ] [MAID-1243](https://maidsafe.atlassian.net/browse/MAID-1243) DNS Lookup
- [ ] [MAID-1244](https://maidsafe.atlassian.net/browse/MAID-1244) Unit tests
- [ ] [MAID-1245](https://maidsafe.atlassian.net/browse/MAID-1245) Create Example to demonstrate the API usage
