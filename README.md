## mbedTLS Integration Examples

This project demostrates integration of mbedTLS and hardware cryptographic modules
such as the ATECC608A.

## Supported hardware
- [AT88CK101](http://www.microchip.com/DevelopmentTools/ProductDetails/AT88CK101SK-MAH-XPRO)
- [CryptoAuthentication Starter Kit (DM320109)](https://www.microchip.com/developmenttools/ProductDetails/DM320109)
- ATECC508A, ATECC608A, ATSHA204A device directly connected via I2C

## Getting Started

### Clone the project and it's submodules

```
git clone --recursive https://github.com/MicrochipTech/mbedtls-examples.git
```

### Select the platform

Windows and Linux use CMAKE for configuration of the project for all other projects
they can be found in the boards directory.

### Configure the device

Build and run the configure program. If the device is already configured this step can be skipped.

### Create the PKI ecosystem

See [scripts/README.md](scripts/README.md) and follow the instructions for setting up a chain of trust

### Provision the device

Build and run the provision program with the provision.h output from the PKI scripts. This will write
the certificate data into the device

### Connect to your service with mutual authentication

Build and run the connect program to use the provisioned device as the secure key storage and hardware
accelerator in your mbedTLS session
