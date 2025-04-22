MFACK is an open source software designed to help acquire nonces and their encrypted parity errors.

This software along with the software provided by Philippe Teuwen in the article "MIFARE Classic: exposing the static encrypted nonce variant" permits to extract the keys of any mifare classic tag that repeats unknown keys in different sectors and that have a default key in a sector.

Please note MFACK is able to recover nonces from target only if it have a known key: default ones (hardcoded in MFACK) or custom ones (user provided using command line).

MRACK was derived from MFOC for ease of implemntation, credit to most of the code goes to the original author.

# Build from source

```
autoreconf -is
./configure
make && sudo make install
```

# Usage #
Put one MIFARE Classic tag that you want keys recovering;
Lauching mfack, you will need to pass options, see
```
mfack -h
```
