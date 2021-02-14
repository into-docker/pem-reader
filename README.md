# pem-reader

A lightweight library to read keys from PEM files.

## Usage

__Leiningen__ ([via Clojars](https://clojars.org/xsc/pem-reader))

[![Clojars Project](http://clojars.org/xsc/pem-reader/latest-version.svg)](http://clojars.org/xsc/pem-reader)

__REPL__

```clojure
(require '[pem-reader.core :as pem])

(def pem (pem/read "test/keys/rsa-private-key.pem"))
;; => #object[pem_reader.core.PEM 0x32c56ed9 "pem_reader.core.PEM@32c56ed9"]

(pem/type pem)
;; => :rsa-private-key

(pem/as-bytes pem)
;; => #object["[B" 0x5698633e "[B@5698633e"]

(pem/private-key pem)
;; => #object[sun.security.rsa.RSAPrivateCrtKeyImpl 0x9a2de04 "sun.security.rsa.RSAPrivateCrtKeyImpl@4940"]

(pem/public-key pem)
;; => nil
```

## Supported Formats

- PKCS#1 (`RSA PRIVATE KEY`)
- PKCS#8 (`PRIVATE KEY`)
- X509 Public Key (`PUBLIC KEY`)
- X509 Certificate (`CERTIFICATE`)

## Rationale

I wanted to read PKCS#1 files and it wasn't easily possible using built-in Java
classes.

## Contributing

Contributions are always welcome. Just make sure the tests are passing.

## License

```
MIT License

Copyright (c) 2015-2021 Yannick Scherer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
