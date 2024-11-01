Teerminal
====

DePHY ID compliant device simulator

## Usage

Clone this repository and run `go build main.go`, then create `config.json` file with the following content:

```json5
{
  "port": "4100", // The port to listen on
  "version": "0.0.1-emulator", // The version of the simulator, can be anything
  "teePlatformVersion": 1, // The security version, bump when security issue has fixed, but may cause incompatibility
  "vendorRoot": "dbbe0cd0b4c7bc4ab34829c96f35bb0011d06dc3bdf0b900401a71a8f7c4c471", // The vendor root key, can be created by running cmd/generate_key
  "rootKey": "cd2f10b3d7d306a27199ccf51868c1b0859f824b6fab53710f06a092ae40226f", // The device key, can be created by running cmd/generate_key, and copied from the output
  "appName": "EmulatorDefault" // The application name, can be anything
}
```

Then run the binary with `./main`.

## API

After you start the service, access the following endpoints:
`/swagger/index.html`

## License

Teerminal is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
