"""
Create an Intermediate Signing Key and Certificate
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
import datetime
import cryptography
import argparse
import pytz
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from create_root import load_or_create_key, random_cert_sn

def create_signer(signer_file, signer_key_file, root_file, root_key_file):
    crypto_be = cryptography.hazmat.backends.default_backend()

    print('\nLoading root CA key')
    if not os.path.isfile(root_key_file):
        raise AWSZTKitError('Failed to find root CA key file, ' + root_key_file + '. Have you run ca_create_root first?')
    with open(root_key_file, 'rb') as f:
        print('    Loading from ' + f.name)
        root_ca_priv_key = serialization.load_pem_private_key(
            data=f.read(),
            password=None,
            backend=crypto_be)

    print('\nLoading root CA certificate')
    if not os.path.isfile(root_file):
        raise AWSZTKitError('Failed to find root CA certificate file, ' + root_file + '. Have you run ca_create_root first?')
    with open(root_file, 'rb') as f:
        print('    Loading from ' + f.name)
        root_ca_cert = x509.load_pem_x509_certificate(f.read(), crypto_be)

    # Create or load a Signer CA key pair
    print('\nSigner CA key')
    signer_ca_priv_key = load_or_create_key(signer_key_file, backend=crypto_be)
        
    # Create signer CA certificate
    print('\nGenerating signer CA certificate from CSR')
    # Please note that the structure of the signer certificate is part of certificate definition in the SAMG55 firmware
    # (g_cert_elements_1_signer). If any part of it is changed, it will also need to be changed in the firmware.
    # The cert2certdef.py utility script can help with regenerating the cert_def_1_signer.c file after making changes.
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(random_cert_sn(16))
    builder = builder.issuer_name(root_ca_cert.subject)
    builder = builder.not_valid_before(datetime.datetime.now(tz=pytz.utc))
    builder = builder.not_valid_after(builder._not_valid_before.replace(year=builder._not_valid_before.year + 10))
    builder = builder.public_key(signer_ca_priv_key.public_key())
    
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, u'Example Inc'),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u'Example Signer FFFF')]))
        
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False),
        critical=True)
    
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(signer_ca_priv_key.public_key()),
        critical=False)

    issuer_ski = root_ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski),
        critical=False)

    # Sign signer certificate with root
    signer_ca_cert = builder.sign(
        private_key=root_ca_priv_key,
        algorithm=hashes.SHA256(),
        backend=crypto_be)

    # Write signer CA certificate to file
    with open(signer_file, 'wb') as f:
        print('    Saving to ' + f.name)
        f.write(signer_ca_cert.public_bytes(encoding=serialization.Encoding.PEM))


if __name__ == '__main__':
    # Create argument parser to document script use
    parser = argparse.ArgumentParser(description='Create an intermediate signer certificate and key based on a supplied root')
    parser.add_argument('--cert', default='signer-ca.crt', help='Certificate file of the signer')
    parser.add_argument('--key', default='signer-ca.key', help='Private Key file of the signer')
    parser.add_argument('--root', default='root-ca.crt', help='Certificate of the root')
    parser.add_argument('--rootkey', default='root-ca.key', help='Private key of the root')
    args = parser.parse_args()
    
    create_signer(args.cert, args.key, args.root, args.rootkey)

    print('\nDone')
    