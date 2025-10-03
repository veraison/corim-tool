A tool for working CoRIMs (Concise Reference Integrity Manifests) based on
[corim-rs](https://github.com/veraison/corim-rs).

## Example Usage

Use `-h`/`--help` option for full options (note: some subcommand-specific
options will only be displayed when specifying the subcommand).

Parse a CoRIM into a JSON representation and write it to STDOUT, while
suppressing log output (quite mode):
```
corim-tool parse -q test/unsigned-good-corim.cbor
```

Parse a CoRIM into a pretty-printed, indented JSON representation and write it
to `/tmp/output.json`.
```
corim-tool parse test/unsigned-good-corim.cbor -p -o /tmp/output.json
```

Compile a JSON representation into an unsigned CoRIM, writing it to
`/tmp/unsigned.cbor`:
```
corim-tool compile test/good-corim.json -o /tmp/unsigned.cbor
```

Compile a JSON representation into an signed CoRIM, signing it with
`test/key.priv.pem`, and writing it to `/tmp/signed.cbor`:
```
corim-tool compile test/good-corim.json -k test/key.priv.pem -o /tmp/signed.cbor
```

Compile a JSON representation into an signed CoRIM, signing it with
`test/key.priv.pem`, using meta data described by `test/meta.json`, and writing
it to `/tmp/signed.cbor`:
```
corim-tool compile test/good-corim.json -k test/key.priv.pem -m test/meta.json -o /tmp/signed.cbor
```

Verifying the signature on a signed CoRIM using `test/key.pub.pem`:
```
corim-tool verify test/signed-good-corim.cbor test/key.pub.pem
```
