# go-btc
[![ReportCard][reportcard-image]][reportcard-url] [![GoDoc][godoc-image]][godoc-url] [![License][license-image]][license-url]

go-btc is a minimalistic library, written purely in Golang, with Bitcoin utility functions.


## Features

- Generate and verify private keys for use on the Bitcoin Blockchain.
- Generate the public key, address and WIF associated with a private key.
- Base58Check encoding, decoding and checksum check utility functions.

go-btc can accept optional parameters as well to work with compressed keys and the testnet.

## AGPL-3.0 License

  Copyright (c) 2019 Cheran Senthilkumar

[reportcard-url]: https://goreportcard.com/report/github.com/cheran-senthil/go-btc
[reportcard-image]: https://goreportcard.com/badge/github.com/cheran-senthil/go-btc
[godoc-url]: https://godoc.org/github.com/cheran-senthil/go-btc/keygen
[godoc-image]: https://godoc.org/github.com/cheran-senthil/go-btc/keygen?status.svg
[license-url]: https://www.gnu.org/licenses/agpl-3.0
[license-image]: https://img.shields.io/badge/License-AGPL%20v3-blue.svg
