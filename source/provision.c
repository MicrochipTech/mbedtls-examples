/**
* \brief This tool is for programming and provisioning of ATECC508 & ATECC608A
* devices for use with AWS IOT
*
* \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
*            You may use this software and any derivatives exclusively with
*            Microchip products.
*
* \page License
*
* (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
* software and any derivatives exclusively with Microchip products.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
* WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*
* MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
* TERMS.
*/

#include "stdio.h"
#include "stdlib.h"
#include "windows.h"

#include "cryptoauthlib.h"
#include "atcacert/atcacert_client.h"
#include "cert_chain.h"

#include "provision.h"

uint8_t device_der_qa[sizeof(provisioning_device_cert) + 8];
uint8_t signer_der_qa[sizeof(provisioning_signer_cert) + 8];

/* Writes the certificates into a device*/
int atca_provision(void)
{
	int ret = 1;
    size_t device_size = sizeof(provisioning_device_cert);
    size_t signer_size = sizeof(provisioning_signer_cert);
	size_t tmp_size;
	ATCA_STATUS status;
	int i;
	bool diff = false;

	/* Start a session */
	if (ATCA_SUCCESS != (status = atcab_init(&cfg_ateccx08a_kithid_default)))
	{
		printf("Failed to init: %d\r\n", status);
		goto exit;
	}

    if (g_cert_def_1_signer.ca_cert_def)
    {
        /* Write the ca public key (signer authority) - normally static data */
        printf("Writing Root Public Key\r\n");
        if (ATCA_SUCCESS != (status = atcab_write_pubkey(g_cert_def_1_signer.ca_cert_def->public_key_dev_loc.slot, 
            provisioning_root_public_key)))
        {
            printf("Failed to write root ca public key\r\n");
            goto exit;
        }
    }

	/* Write the signer certificate */
	printf("Writing Signer Certificate\r\n");
	if (ATCA_SUCCESS != (status = atcacert_write_cert(&g_cert_def_1_signer, provisioning_signer_cert, g_cert_def_1_signer.cert_template_size)))
	{
		printf("Failed to write signer certificate: %d\r\n", status);
		goto exit;
	}

	/* Write the device certificate */
	printf("Writing Device Certificate\r\n");
	if (ATCA_SUCCESS != (status = atcacert_write_cert(&g_cert_def_2_device, provisioning_device_cert, g_cert_def_2_device.cert_template_size)))
	{
		printf("Failed to write device certificate: %d\r\n", status);
		goto exit;
	}

	/* Read back the signer certificate */
	tmp_size = signer_size + 4;
	printf("Reading Signer Certificate\r\n");
	if (ATCA_SUCCESS != (status = atcacert_read_cert(&g_cert_def_1_signer, provisioning_root_public_key, signer_der_qa, &tmp_size)))
	{
		printf("Failed to read signer certificate: %d\r\n", status);
		goto exit;
	}

	/* Compare the signer certificate */
	printf("Comparing Signer Certificate\r\n");
	if (memcmp(provisioning_signer_cert, signer_der_qa, signer_size))
	{
		printf("Signer certificate missmatch\r\n");
		diff = false;
		for (i = 0; i < signer_size; i++)
		{
			if (provisioning_signer_cert[i] != signer_der_qa[i])
			{
				diff = true;
			}

			if (0 == (i % 16))
			{
				printf("%s\r\n%04X: ", diff?"*":"", i);
				diff = false;
			}
			printf("%02X|%02X ", provisioning_signer_cert[i], signer_der_qa[i]);
		}
	}

	/* Read back the device certificate */
	tmp_size = device_size + 4;
	printf("Reading Device Certificate\r\n");
	if (ATCA_SUCCESS != (status = atcacert_read_cert(&g_cert_def_2_device,
		&signer_der_qa[g_cert_def_1_signer.std_cert_elements[0].offset],
		device_der_qa, &tmp_size)))
	{
		printf("Failed to read device certificate: %d\r\n", status);
	}

	/* Compare the device certificate */
	printf("Comparing Device Certificate\r\n");
	if (memcmp(provisioning_device_cert, device_der_qa, device_size))
	{
		printf("Signer certificate missmatch\r\n");

		diff = false;
		for (i = 0; i < device_size; i++)
		{
			if (provisioning_device_cert[i] != device_der_qa[i])
			{
				diff = true;
			}

			if (0 == (i % 16))
			{
				printf("%s\r\n%04X: ", diff ? "*" : "", i);
				diff = false;
			}
			printf("%02X|%02X ", provisioning_device_cert[i], device_der_qa[i]);
		}
	}

	printf("\r\nDevice Provisioning Successful!\r\n");

	/* End the session */
	atcab_release();


exit:
	return ret;
}

int main(int argc, char *argv[])
{
    return atca_provision();
}