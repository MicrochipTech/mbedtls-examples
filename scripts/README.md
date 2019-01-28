# Microchip Secure Element Tools

These tools are used to set up an example chain of trust ecosystem for use with
Microchip ATECC508A and ATECC608A parts. Included are utilities to create the
ecosystem keys and certificates.

## Dependencies

Python scripts will require python 3 to be installed. Once python is installed
install the requirements (from the path of this file):

```
> pip install -r requirements.txt
```

The application will have to built by loading the microchip_security_tool.sln
project file and building either the x86 or x64 version of the application


## Set up a Certificate Ecosystem

The first step is to set up a certificate chain that mirrors how a secure iot
ecosystem would be configured. For this we'll create a dummy root certificate
authority (normally this would be handled by a third party, or an internal
PKI system) and an intermediate certificate authority that mirrors the signing
hardware security modules (HSM) that are used in the Microchip facility during
manufacturing of security devices.

### Create the Root CA

```
> create_root.py 
```

### Create the Signing CA

```
> create_signer.py
```

### Create the Device Certificate

1) Output from the configure.c program would be the public key required for an
certificate:

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEojEQk85EaT1RU3Ip5SddaSqB5/Wm
+Vnxtu96G3i+gQRb8tb5xylXTXHQawL68SPW4/oCXXS4x7KGV0MNPneB6g==
-----END PUBLIC KEY-----
```

3) Save this key as public_key.pem for use in the device certificate creation

4) Run the create_device script:

```
> create_device.py <public_key.pem>
```

This step mirrors the production provisioning process where Microchip uses HSMs
to sign each device produced and loads the certificate information into them.
This performs the certificate creation and signing process but does not load the
certificates into the device (provisioning).

### Export the provision.h file

> export_header.py

This creates the file that is used by provision.c to save the generated
certificates into the secure element. 

### Run the provisioning

A call to atca_provision() in provision.c will write the certificates into
the device.
