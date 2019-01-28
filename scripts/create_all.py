"""
Create an entire PKI ecosystem
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
import argparse
from create_root import create_root
from create_signer import create_signer
from create_device import create_device
from export_header import create_output_file

if __name__ == '__main__':
    # Create argument parser to document script use
    parser = argparse.ArgumentParser(description='Provisions the kit by creating an ecosystem and creating a device certificate')
    parser.add_argument('--out', default='provision.h', help='Provisioning Header File')
    parser.add_argument('--device', default='device.crt', help='[OUT] Device Certificate (PEM)')
    parser.add_argument('--devicekey', default='device-pub.pem', help='[IN] Device Public Key (PEM)')
    parser.add_argument('--signer', default='signer-ca.crt', help='[IN] Certificate file of the signer')
    parser.add_argument('--signerkey', default='signer-ca.key', help='[IN] Private Key file of the signer')
    parser.add_argument('--root', default='root-ca.crt', help='[IN] Root Certificate of the chain')
    parser.add_argument('--rootkey', default='root-ca.key', help='[IN] Root Private key (PEM)')
    parser.add_argument('--rootpub', default='root-pub.pem', help='[OUT] Root Public key (PEM)')
    args = parser.parse_args()

    # Create a root key and certificate if they doesn't exist
    if not (os.path.exists(args.root) and os.path.exists(args.rootkey)):
        create_root(args.root, args.rootkey)
    
    # Create an intermediate (signer) key and certificate is they don't exist
    if not (os.path.exists(args.signer) and os.path.exists(args.signerkey)):
        create_signer(args.signer, args.signerkey, args.root, args.rootkey)
    
    # Create a device certificate if it does not exist
    if not os.path.exists(args.device):
        create_device(args.device, args.devicekey, args.signer, args.signerkey, args.root, args.rootpub)

    create_output_file(args.out, args.root, args.device, args.signer)