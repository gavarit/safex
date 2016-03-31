[![Build Status](https://travis-ci.org/safex/safex.png?branch=master)](https://travis-ci.org/safex/safex)

# safex

#install
### Building from source

##### Ubuntu 14.04, 15.04, 15.10

#### Install Rust Stable

```bash

# install rust stable
curl -sf https://raw.githubusercontent.com/brson/multirust/master/blastoff.sh | sh

# install stable and make it default
sudo multirust update stable
sudo multirust default stable
```

##### OSX with Homebrew

```bash
# install multirust
brew update
brew install multirust

# install stable and make it default
multirust update stable && multirust default stable
```



#### Generate keys

```bash
# download and build safex/safex
git clone https://github.com/safex/safex
cd safex
cargo run --example keys
```
#### Import base64 bitcoin private key

```bash
# download and build safex/safex
git clone https://github.com/safex/safex
cd safex
cargo run --example import
```
#### Run some tests

```bash
# download and build safex/safex
git clone https://github.com/safex/safex
cd safex
cargo run --example testkeys
```