This folder is a quick and dirty extract of https://github.com/RfidResearchGroup/proxmark3/blob/master/tools/mfc/card_only/staticnested_0nt.c and all the required files from there. All credit goes to them.

# Build from source

```
gcc *.c *.h crapto1/*.c crapto1/*.h -o staticnested_0nt.exe
```

# Usage #
Get the nonce and their encoded parity bits, once you have them launch staticnested_0nt.exe with the correct arguments, for a description of the arguents execute
```
staticnested_0nt.exe
```

