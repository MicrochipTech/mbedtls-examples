"""
Convert PKI Certificates into a provisioning header file
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

import argparse
from string import Template

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

PROVISION_H_TEMPLATE = Template("""
static const uint8_t provisioning_device_cert[] = {
${device_certificate}};

static const uint8_t provisioning_signer_cert[] = {
${signer_certificate}};

static const uint8_t provisioning_root_public_key[] = {
${root_public_key}};
""")

def convert_bytes_to_c_bytes(a, l=16, indent=''):
    """
    Format a list/bytes/bytearray object into a formatted ascii hex string
    """
    s = ''
    a = bytearray(a)
    for x in range(0, len(a), l):
        s += indent + ''.join(['0x%02X, ' % y for y in a[x:x+l]]) + '\n'
    return s

def create_output_file(outfile, rootfile, devicefile, signerfile):
    d = {}

    with open(rootfile, 'rb') as f:
        root_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        root_key_bytes = root_cert.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        d['root_public_key'] = convert_bytes_to_c_bytes(root_key_bytes[1:], indent='    ')

    with open(devicefile, 'rb') as f:
        device_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        device_cert_bytes = device_cert.public_bytes(serialization.Encoding.DER)
        d['device_certificate'] = convert_bytes_to_c_bytes(device_cert_bytes, indent='    ')

    with open(signerfile, 'rb') as f:
        signer_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        signer_cert_bytes = signer_cert.public_bytes(serialization.Encoding.DER)
        d['signer_certificate'] = convert_bytes_to_c_bytes(signer_cert_bytes, indent='    ')

    s = PROVISION_H_TEMPLATE.substitute(d)

    with open(outfile, 'w') as f:
        f.write(s)


if __name__ == '__main__':
    # Create argument parser to document script use
    parser = argparse.ArgumentParser(description='Export certificate data as C definitions')
    parser.add_argument('--out', default='provision.h', help='Provisioning Header File')
    parser.add_argument('--device', default='device.crt', help='Device Certificate')
    parser.add_argument('--signer', default='signer-ca.crt', help='Signer (jitr) Certificate')
    parser.add_argument('--root', default='root-ca.crt', help='Root Certificate')

    args = parser.parse_args()

    create_output_file(args.out, args.root, args.device, args.signer)

    print('\nDone')
