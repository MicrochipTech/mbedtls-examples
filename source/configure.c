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

static int8_t atecc508_configuration[] = {
    0xC0, 0x00, 0x55, 0x00, 0x8F, 0x20, 0xC4, 0x44, 0x87, 0x20, 0x87, 0x20, 0x8F, 0x0F, 0xC4, 0x36,
    0x9F, 0x0F, 0x82, 0x20, 0x0F, 0x0F, 0xC4, 0x44, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x13, 0x00, 0x7C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x33, 0x00,
    0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00
};

static uint8_t atecc608_configuration[] = {
    0xC0, 0x00, 0x00, 0x01, 0x8F, 0x20, 0xC4, 0x44, 0x87, 0x20, 0x87, 0x20, 0x8F, 0x0F, 0xC4, 0x36,
    0x9F, 0x0F, 0x82, 0x20, 0x0F, 0x0F, 0xC4, 0x44, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x13, 0x00, 0x7C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x33, 0x00,
    0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x30, 0x00,
};

const uint8_t public_key_x509_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04
};

void print_public_key(uint8_t pubkey[ATCA_PUB_KEY_SIZE])
{
    uint8_t buf[128];
    uint8_t * tmp;
    size_t buf_len = sizeof(buf);

    /* Calculate where the raw data will fit into the buffer */
    tmp = buf + sizeof(buf) - ATCA_PUB_KEY_SIZE - sizeof(public_key_x509_header);

    /* Copy the header */
    memcpy(tmp, public_key_x509_header, sizeof(public_key_x509_header));

    /* Copy the key bytes */
    memcpy(tmp + sizeof(public_key_x509_header), pubkey, ATCA_PUB_KEY_SIZE);

    /* Convert to base 64 */
    (void)atcab_base64encode(tmp, ATCA_PUB_KEY_SIZE + sizeof(public_key_x509_header), buf, &buf_len);

    /* Add a null terminator */
    buf[buf_len] = 0;

    /* Print out the key */
    printf("-----BEGIN PUBLIC KEY-----\r\n%s\r\n-----END PUBLIC KEY-----\r\n", buf);
}

int atca_configure(uint8_t i2c_addr)
{
    ATCA_STATUS status;
    char    accept = '0';
    uint8_t buf[ATCA_BLOCK_SIZE];
    bool    lock = false;
    uint8_t pubkey[ATCA_PUB_KEY_SIZE];

    /* Initialize the interface */
    if (ATCA_SUCCESS != (status = atcab_init(&cfg_ateccx08a_kithid_default)))
    {
        printf("Unable to initialize interface: %x\r\n", status);
        goto exit;
    }

    /* Check the config zone lock status */
    if (ATCA_SUCCESS != (status = atcab_is_locked(ATCA_ZONE_CONFIG, &lock)))
    {
        printf("Unable to get config lock status: %x\r\n", status);
        goto exit;
    }

    /* Get the device type */
    if (ATCA_SUCCESS != (status = atcab_info(buf)))
    {
        printf("Unable to read revision: %x\r\n", status);
        goto exit;
    }
    
    /* Program the configuration zone */
    if (!lock)
    {
        if (0x50 == buf[2])
        {
            if (i2c_addr != atecc508_configuration[0])
            {
                atecc508_configuration[0] = i2c_addr;
            }
            status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, atecc508_configuration, sizeof(atecc508_configuration));
        }
        else if (0x60 == buf[2])
        {
            if (i2c_addr != atecc608_configuration[0])
            {
                atecc608_configuration[0] = i2c_addr;
            }
            status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, atecc608_configuration, sizeof(atecc608_configuration));
        }
        else
        {
            printf("Device is not recognized: 0x%02x\r\n", buf[2]);
            goto exit;
        }

        if (ATCA_SUCCESS != status)
        {
            printf("Unable to program config zone: %x\r\n", status);
            goto exit;
        }

        /* Lock the config zone */
        if (ATCA_SUCCESS != (status = atcab_lock_config_zone()))
        {
            printf("Unable to lock config zone: %x\r\n", status);
            goto exit;
        }
    }

    /* Check data zone lock */
    if (ATCA_SUCCESS != (status = atcab_is_locked(LOCK_ZONE_DATA, &lock)))
    {
        printf("Unable to get data lock status: %x\r\n", status);
        goto exit;
    }

    /* Lock the data zone */
    if (!lock)
    {
        if (ATCA_SUCCESS != (status = atcab_lock_data_zone()))
        {
            printf("Unable to lock data zone: %x\r\n", status);
            goto exit;
        }
    }

    /* Generate new keys */
    if (ATCA_SUCCESS != (status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0, NULL, pubkey)))
    {
        printf("Genkey on slot 0 failed: %x\r\n", status);
        goto exit;
    }
    else
    {
        print_public_key(pubkey);
    }

    if (ATCA_SUCCESS != (status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 2, NULL, NULL)))
    {
        printf("Genkey on slot 2 failed: %x\r\n", status);
    }

    if (ATCA_SUCCESS != (status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 3, NULL, NULL)))
    {
        printf("Genkey on slot 3 failed: %x\r\n", status);
    }

    if (ATCA_SUCCESS != (status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 7, NULL, NULL)))
    {
        printf("Genkey on slot 7 failed: %x\r\n", status);
    }

    printf("Configuration Complete\r\n");

exit:
    return status;
}

int main(int argc, char *argv[])
{
    return atca_configure(0xC0);
}