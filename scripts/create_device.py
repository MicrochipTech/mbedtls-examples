"""
Create a Device Certificate with a given Public Key
"""
# (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
#
# Subject to your compliance with these terms, you may use Microchip software
# and any derivatives exclusively with Microchip products. It is your
# responsibility to comply with third party license terms applicable to your
# use of third party software (including open source software) that may
# accompany Microchip software.
#
# THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
# EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
# WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
# PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
# SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
# OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
# MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
# FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
# LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
# THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
# THIS SOFTWARE.

import os
import hid
import base64
import argparse
import pytz

import datetime
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


def device_cert_sn(size, builder):
    """Cert serial number is the SHA256(Subject public key + Encoded dates)"""

    # Setup cryptography
    be = cryptography.hazmat.backends.default_backend()

    # Get the public key as X and Y integers concatenated
    pub_nums = builder._public_key.public_numbers()
    pubkey =  pub_nums.x.to_bytes(32, byteorder='big', signed=False)
    pubkey += pub_nums.y.to_bytes(32, byteorder='big', signed=False)

    # Get the encoded dates
    expire_years = 0
    enc_dates = bytearray(b'\x00'*3)
    enc_dates[0] = (enc_dates[0] & 0x07) | ((((builder._not_valid_before.year - 2000) & 0x1F) << 3) & 0xFF)
    enc_dates[0] = (enc_dates[0] & 0xF8) | ((((builder._not_valid_before.month) & 0x0F) >> 1) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x7F) | ((((builder._not_valid_before.month) & 0x0F) << 7) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0x83) | (((builder._not_valid_before.day & 0x1F) << 2) & 0xFF)
    enc_dates[1] = (enc_dates[1] & 0xFC) | (((builder._not_valid_before.hour & 0x1F) >> 3) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0x1F) | (((builder._not_valid_before.hour & 0x1F) << 5) & 0xFF)
    enc_dates[2] = (enc_dates[2] & 0xE0) | ((expire_years & 0x1F) & 0xFF)
    enc_dates = bytes(enc_dates)

    # SAH256 hash of the public key and encoded dates
    digest = hashes.Hash(hashes.SHA256(), backend=be)
    digest.update(pubkey)
    digest.update(enc_dates)
    raw_sn = bytearray(digest.finalize()[:size])
    raw_sn[0] = raw_sn[0] & 0x7F # Force MSB bit to 0 to ensure positive integer
    raw_sn[0] = raw_sn[0] | 0x40 # Force next bit to 1 to ensure the integer won't be trimmed in ASN.1 DER encoding
    return int.from_bytes(raw_sn, byteorder='big', signed=False)


def create_device(device_file, device_key_file, signer_file, signer_key_file, root_file, root_key_file):
    # Make sure files exist
    if not (os.path.isfile(signer_file) and os.path.isfile(signer_key_file) and os.path.isfile(root_file)):
        raise FileNotFoundError('Failed to find {}, {}, or {}'.format(signer_file, signer_key_file, root_file))

    # Setup cryptography
    be = cryptography.hazmat.backends.default_backend()

    print('\nLoad Device Public Key')
    # Load the public key from the device or a file
    print('    Loading from %s' % device_key_file)
    with open(device_key_file, 'r') as f:
        public_key_pem = f.read()

    # Convert the key into the cryptography format
    public_key = serialization.load_pem_public_key(public_key_pem.encode('ascii'), be)
    
    print('\nLoad Signer')
    # Load the Signing key from the file
    print('    Loading key from %s' % signer_key_file)
    with open(signer_key_file, 'rb') as f:
        signer_ca_priv_key = serialization.load_pem_private_key(data=f.read(), password=None, backend=be)

    # Load the Signing Certificate from the file
    print('    Loading certificate from %s' % signer_file)
    with open(signer_file, 'rb') as f:
        signer_ca_cert = x509.load_pem_x509_certificate(f.read(), be)

    with open(root_file, 'rb') as f:
        root_ca_cert = x509.load_pem_x509_certificate(f.read(), be)
        root_public = root_ca_cert.public_key()

    # Build certificate
    print('\nCreate Device Certificate')
    builder = x509.CertificateBuilder()

    builder = builder.issuer_name(signer_ca_cert.subject)

    # Device cert must have minutes and seconds set to 0
    builder = builder.not_valid_before(datetime.datetime.now(tz=pytz.utc).replace(minute=0,second=0))

    # Should be year 9999, but this doesn't work on windows
    builder = builder.not_valid_after(datetime.datetime(3000, 12, 31, 23, 59, 59))

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'Example Inc'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Example Device')]))

    builder = builder.public_key(public_key)

    # Device certificate is generated from certificate dates and public key
    builder = builder.serial_number(device_cert_sn(16, builder))

    # Subject Key ID is used as the thing name and MQTT client ID and is required for this demo
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False)

    issuer_ski = signer_ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
        critical=False)

    # Sign certificate 
    device_cert = builder.sign(private_key=signer_ca_priv_key, algorithm=hashes.SHA256(), backend=be)

    # Save certificate for reference
    print('    Save Device Certificate to %s' % device_file)
    with open(device_file, 'wb') as f:
        f.write(device_cert.public_bytes(encoding=serialization.Encoding.PEM))

    # Save root public key
    print('    Save Root Public Key to %s' % root_key_file)
    with open(root_key_file, 'wb') as f:
        f.write(root_public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    

if __name__ == '__main__':
    # Create argument parser to document script use
    parser = argparse.ArgumentParser(description='Provisions the kit by requesting a CSR and returning signed certificates.')
    parser.add_argument('--device', default='device.crt', help='Device Certificate (PEM)')
    parser.add_argument('--devicekey', default='device-pub.pem', help='[IN/OUT] Device Public Key (PEM)')
    parser.add_argument('--signer', default='signer-ca.crt', help='Certificate file of the signer')
    parser.add_argument('--signerkey', default='signer-ca.key', help='Private Key file of the signer')
    parser.add_argument('--root', default='root-ca.crt', help='Root Certificate of the chain')
    parser.add_argument('--rootkey', default='root-pub.pem', help='Root public key (PEM)')
    args = parser.parse_args()

    create_device(args.device, args.devicekey, args.signer, args.signerkey, args.root, args.rootkey)
    
    print('\nDone')
