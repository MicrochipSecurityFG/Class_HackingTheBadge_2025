/**
  Crypto Authentication Basics MASTERS Lab

  @Company
    Microchip Technology Inc.

  @File Name
    configure_atca.c

  @Summary
    This file implements basic communication and authentication with the ECC508A
	
  @Author
    C40249
 */

/*
    (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
    software and any derivatives exclusively with Microchip products.

    THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
    EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
    WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
    PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
    WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.

    IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
    INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
    WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
    BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
    FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
    ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
    THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.

    MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
    TERMS.
 */
#include <stddef.h>
#include <stdbool.h>
#include "util.h"
#include "cryptoauthlib.h"
#include "host/atca_host.h"
#include "secure_element.h"
#include "sha256.h"

const uint8_t mcu_key[] = {0x7d, 0x7b, 0xf6, 0x58, 0x71, 0xfb, 0xb5, 0xac,
    0xec, 0x78, 0xb9, 0x11, 0xe4, 0x79, 0x3c, 0x4a,
    0x2b, 0x3b, 0xa5, 0x3e, 0x98, 0x9e, 0xf7, 0xac,
    0xe2, 0x9a, 0xb6, 0x59, 0xa2, 0xc2, 0xe5, 0xf8};

uint8_t disk_key[] = {0x56, 0x16, 0xd1, 0xe2, 0x27, 0x1b, 0x79, 0xae,
    0x49, 0x55, 0xaf, 0x8e, 0x49, 0x07, 0x46, 0x1a,
    0xc6, 0x9d, 0x2a, 0xe3, 0x6e, 0x22, 0x97, 0x15,
    0x0f, 0xde, 0xd0, 0x75, 0x04, 0x4d, 0x5a, 0xb3};

// Constants for slot 8
#define SLOT_8_NUM_BLOCKS  13
#define SLOT_8_BLOCK_SIZE  32
#define SLOT_8_TOTAL_SIZE  (SLOT_8_NUM_BLOCKS * SLOT_8_BLOCK_SIZE)  // 416 bytes

// Constants for slot 8
#define SLOT_5_NUM_BLOCKS  2
#define SLOT_5_BLOCK_SIZE  32
#define SLOT_5_TOTAL_SIZE  36  // 36 bytes

/*
<ConfigurationZone>
  <SN01>01 23</SN01>
  <SN8>EE</SN8>
  <AESEnable>61</AESEnable>
  <I2CEnable>51</I2CEnable>
  <I2CAddress>C0</I2CAddress>
  <Reserved Address="17" Size="1">00</Reserved>
  <CountMatch>31</CountMatch>
  <ChipMode>00</ChipMode>
  <SlotConfigurations Size="16">

    <!-- Disk Encryption Key -->
    <SlotConfiguration Index="0">E1 42</SlotConfiguration>

    <!-- User Key - H(pin + mcu key) -->
    <SlotConfiguration Index="1">AF 40</SlotConfiguration>

    <!-- MCU Key -->
    <SlotConfiguration Index="2">8F 0F</SlotConfiguration>

    <!-- Counter 0 Limit -->
    <SlotConfiguration Index="3">C2 40</SlotConfiguration>

    <!-- AES Key -->
    <SlotConfiguration Index="4">0F 0F</SlotConfiguration>

    <!-- Last Good Login -->
    <SlotConfiguration Index="5">0F 0F</SlotConfiguration>
    <SlotConfiguration Index="6">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="7">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="8">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="9">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="A">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="B">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="C">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="D">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="E">8F 8F</SlotConfiguration>
    <SlotConfiguration Index="F">9F 8F</SlotConfiguration>
  </SlotConfigurations>
  <Counter0 Size="8">00 00 7F FF 00 00 00 00</Counter0>
  <Counter1 Size="8">FF FF FF FF 00 00 00 00</Counter1>
  <UseLock>00</UseLock>
  <VolatileKeyPermission>00</VolatileKeyPermission>
  <SecureBoot Size="2">00 00</SecureBoot>
  <KdfIvLoc>00</KdfIvLoc>
  <KdfIvStr Size="2">00 00</KdfIvStr>
  <Reserved Address="75" Size="9">00 00 00 00 00 00 00 00 00</Reserved>
  <UserExtra>00</UserExtra>
  <UserExtraAdd>00</UserExtraAdd>
  <SlotLocked>FF FF</SlotLocked>
  <ChipOptions Size="2">03 5D</ChipOptions>
  <X509format>00 00 00 00</X509format>
  <KeyConfigurations Size="16">
    <KeyConfiguration Index="0">DC 02</KeyConfiguration>
    <KeyConfiguration Index="1">DC 02</KeyConfiguration>
    <KeyConfiguration Index="2">7C 0F</KeyConfiguration>
    <KeyConfiguration Index="3">DC 02</KeyConfiguration>
    <KeyConfiguration Index="4">38 0F</KeyConfiguration>
    <KeyConfiguration Index="5">3C 0F</KeyConfiguration>
    <KeyConfiguration Index="6">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="7">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="8">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="9">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="A">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="B">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="C">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="D">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="E">1C 0F</KeyConfiguration>
    <KeyConfiguration Index="F">DC 0F</KeyConfiguration>
  </KeyConfigurations>
</ConfigurationZone>
 */

//oblige service lounge travel please burger address shrimp forward van era purchase

static void ManageAESExportKey() {
    ATCA_STATUS status;
    uint16_t slot = 0x04; // slot is slot 4 (assigned to Export AES Key)
    size_t offset_bytes = 0x00; // no offset bytes   
    uint8_t exportKey[32] = {
        0x32, 0xC3, 0x76, 0xEC, 0xA6, 0x3C, 0xC4, 0x1E, 0x18, 0x0E, 0x12, 0xBD, 0xEC, 0xD5, 0x77, 0x12
    };

    // Write random number to slot 4 - the IO Protection Key Slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, offset_bytes, exportKey, 32);
    CHECK_STATUS(status);

    printf("AES Export Key Written Successfully.\n");

}

void SECURE_ELEMENT_GetSerial(uint8_t * serial) {

	ATCA_STATUS status;
	memset(serial, 0xFF, 9);
	status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0x00, serial, 9 - 1);
	CHECK_STATUS(status);

}

int SECURE_ELEMENT_ReadSlot8(uint8_t *data, size_t length) {
    int status;

    // Check if requested length exceeds slot size
    if (length > SLOT_8_TOTAL_SIZE) {
        printf("Error: Read length %zu exceeds slot 8 capacity %d\n", length, SLOT_8_TOTAL_SIZE);
        return -1;  // Custom error code
    }

    printf("Reading %zu bytes from Slot 8\n", length);

    // Read full 32-byte blocks
    size_t offset = 0;
    while (length >= SLOT_8_BLOCK_SIZE) {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 8, offset, data, SLOT_8_BLOCK_SIZE);
        CHECK_STATUS(status);
        data += SLOT_8_BLOCK_SIZE;
        length -= SLOT_8_BLOCK_SIZE;
        offset += SLOT_8_BLOCK_SIZE;
    }

    // Read remaining partial block (if any)
    if (length > 0) {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 8, offset, data, length);
        CHECK_STATUS(status);
    }

    return ATCA_SUCCESS;
}

int SECURE_ELEMENT_ReadSlot5(uint8_t *data, size_t length) {
    int status;

    // Check if requested length exceeds slot size
    if (length > SLOT_5_TOTAL_SIZE) {
        printf("Error: Read length %zu exceeds slot 8 capacity %d\n", length, SLOT_5_TOTAL_SIZE);
        return -1;  // Custom error code
    }

    printf("Reading %zu bytes from Slot 8\n", length);

    // Read full 32-byte blocks
    size_t offset = 0;
    while (length >= SLOT_5_BLOCK_SIZE) {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 5, offset, data, SLOT_5_BLOCK_SIZE);
        CHECK_STATUS(status);
        data += SLOT_5_BLOCK_SIZE;
        length -= SLOT_5_BLOCK_SIZE;
        offset += SLOT_5_BLOCK_SIZE;
    }

    // Read remaining partial block (if any)
    if (length > 0) {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 5, offset, data, length);
        CHECK_STATUS(status);
    }

    return ATCA_SUCCESS;
}

int SECURE_ELEMENT_WriteSlot8(const uint8_t *data, size_t length) {
    int status;

    // Check if data exceeds slot size
    if (length > SLOT_8_TOTAL_SIZE) {
        printf("Error: Data length %zu exceeds slot 8 capacity %d\n", length, SLOT_8_TOTAL_SIZE);
        return -1;  // Custom error code (adjust to your API's convention)
    }

    printf("Writing %zu bytes to Slot 8\n", length);

    // Write full 32-byte blocks
    size_t offset = 0;
    while (length >= SLOT_8_BLOCK_SIZE) {
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 8, offset, data, SLOT_8_BLOCK_SIZE);
        CHECK_STATUS(status);
        data += SLOT_8_BLOCK_SIZE;
        length -= SLOT_8_BLOCK_SIZE;
        offset += SLOT_8_BLOCK_SIZE;
    }

    // Write remaining partial block (if any), rounding up to the nearest 4-byte boundary
    if (length > 0) {
        size_t padded_length = (length + 3) & ~3; // Round up to next multiple of 4

        uint8_t padded_data[padded_length];
        memcpy(padded_data, data, length);
        memset(padded_data + length, 0, padded_length - length); // Zero-fill padding

        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 8, offset, padded_data, padded_length);
        CHECK_STATUS(status);
    }

    return ATCA_SUCCESS;
}

int SECURE_ELEMENT_WriteSlot5(const uint8_t *data, size_t length) {
    int status;

    // Check if data exceeds slot size
    if (length > SLOT_5_TOTAL_SIZE) {
        printf("Error: Data length %zu exceeds slot 8 capacity %d\n", length, SLOT_5_TOTAL_SIZE);
        return -1;  // Custom error code (adjust to your API's convention)
    }

    printf("Writing %zu bytes to Slot 5\n", length);

    // Write full 32-byte blocks
    size_t offset = 0;
    while (length >= SLOT_5_BLOCK_SIZE) {
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 5, offset, data, SLOT_5_BLOCK_SIZE);
        CHECK_STATUS(status);
        data += SLOT_5_BLOCK_SIZE;
        length -= SLOT_5_BLOCK_SIZE;
        offset += SLOT_5_BLOCK_SIZE;
    }

    // Write remaining partial block (if any), rounding up to the nearest 4-byte boundary
    if (length > 0) {
        size_t padded_length = (length + 3) & ~3; // Round up to next multiple of 4

        uint8_t padded_data[padded_length];
        memcpy(padded_data, data, length);
        memset(padded_data + length, 0, padded_length - length); // Zero-fill padding

        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 5, offset, padded_data, padded_length);
        CHECK_STATUS(status);
    }

    return ATCA_SUCCESS;
}

uint8_t SECURE_ELEMENT_WriteConfig(uint8_t addr) {

    //generated C HEX from javascript config tool
    const uint8_t eccx08_config[] = {
    		0x01, 0x23, 0xFC, 0x1D, 0x00, 0x00, 0x60, 0x03,  0xCC, 0xDA, 0x5A, 0xB6, 0xEE, 0x61, 0x51, 0x00,
    		0xC0, 0x00, 0x31, 0x00, 0xE1, 0x42, 0xAF, 0x40,  0x8F, 0x0F, 0xC2, 0x40, 0x0F, 0x0F, 0x0F, 0x0F,
    		0x8F, 0x8F, 0x8F, 0x8F, 0x0F, 0x0F, 0x8F, 0x8F,  0x8F, 0x8F, 0x8F, 0x8F, 0x8F, 0x8F, 0x8F, 0x8F,
    		0x8F, 0x8F, 0x9F, 0x8F, 0x00, 0x00, 0x7F, 0xFF,  0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0xFF, 0xFF, 0x03, 0x5D, 0x00, 0x00, 0x00, 0x00,
    		0xDC, 0x02, 0xDC, 0x02, 0x7C, 0x0F, 0xDC, 0x02,  0x38, 0x0F, 0x3C, 0x0F, 0x1C, 0x0F, 0x1C, 0x0F,
    		0x1C, 0x0F, 0x1C, 0x0F, 0x1C, 0x0F, 0x1C, 0x0F,  0x1C, 0x0F, 0x1C, 0x0F, 0x1C, 0x0F, 0xDC, 0x0F
    };

    ATCA_STATUS status = ATCA_GEN_FAIL;

    bool islocked;

    printf("--Write Configuration--\n");

    status = atcab_init(&atecc608_0_init_data);
    CHECK_STATUS(status);

    uint8_t data[128];
    status = atcab_read_config_zone((uint8_t*) & data);

    if (status != ATCA_SUCCESS) { // Try other address
        atecc608_0_init_data.atcai2c.address = addr;
        status = atcab_init(&atecc608_0_init_data);
        CHECK_STATUS(status);

        status = atcab_read_config_zone((uint8_t*) & data);
    }

    CHECK_STATUS(status);

    UTIL_PrintArray((uint8_t*) & data, 128);

    status = atcab_is_locked(LOCK_ZONE_CONFIG, &islocked);
    CHECK_STATUS(status);

    if (islocked) {
        printf("ATCA already configured\n");
        return 0;
    }

    status = atcab_is_locked(LOCK_ZONE_DATA, &islocked);
    CHECK_STATUS(status);
    
    if (islocked) {
        printf("ATCA - Error\n");
        while (status != ATCA_SUCCESS);
    }

    status = atcab_write_config_zone(eccx08_config);
    CHECK_STATUS(status);

    status = atcab_lock_config_zone();
    CHECK_STATUS(status);

    if (status != ATCA_SUCCESS) {
        printf("ATCA - Error\n");
        while (status != ATCA_SUCCESS);
    }

    printf("Write Complete\n");

    return 1;
}

void SECURE_ELEMENT_WriteData() {

    uint8_t key2[] = {0x7d, 0x7b, 0xf6, 0x58, 0x71, 0xfb, 0xb5, 0xac,
        0xec, 0x78, 0xb9, 0x11, 0xe4, 0x79, 0x3c, 0x4a,
        0x2b, 0x3b, 0xa5, 0x3e, 0x98, 0x9e, 0xf7, 0xac,
        0xe2, 0x9a, 0xb6, 0x59, 0xa2, 0xc2, 0xe5, 0xf8};

    uint8_t key4[] = {0x56, 0x16, 0xd1, 0xe2, 0x27, 0x1b, 0x79, 0xae,
        0x49, 0x55, 0xaf, 0x8e, 0x49, 0x07, 0x46, 0x1a,
        0xc6, 0x9d, 0x2a, 0xe3, 0x6e, 0x22, 0x97, 0x15,
        0x0f, 0xde, 0xd0, 0x75, 0x04, 0x4d, 0x5a, 0xb3};

    ATCA_STATUS status = ATCA_GEN_FAIL;

    printf("--Write Data Zone--\n");

    //atecc608_0_init_data.atcai2c.slave_address = 0xB0;
    status = atcab_init(&atecc608_0_init_data);
    CHECK_STATUS(status);

    bool locked = false;
    status = atcab_is_locked(LOCK_ZONE_DATA, &locked);
    CHECK_STATUS(status);

    if (locked) {
        printf("DataZone already configured\n");

    } else {

        printf("Writing Slot 2\n"); //MCU Key
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 2, 0, key2, 32);
        CHECK_STATUS(status);
        printf("Writing Slot 4\n"); //AES Key
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 4, 0, key4, 32);
        CHECK_STATUS(status);

        uint8_t counterValue[32] = {0xff};
        counterValue[0] = 0xfe;
        counterValue[4] = 0xfe;

        printf("Writing Slot 3\n"); //Limit value
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 3, 0, (uint8_t*) &counterValue, 32);
        CHECK_STATUS(status);

        ManageAESExportKey();
        
        printf("Write Complete\n");

        printf("Locking Data Zone\n");
        
        status = atcab_lock_data_zone();
        CHECK_STATUS(status);

        printf("Complete\n");
    }
}

int SECURE_ELEMENT_SlotAuth(uint8_t slot, const uint8_t * key) {
    //Step 2.1
    ATCA_STATUS status;
    uint8_t sn[9];
    status = atcab_read_serial_number(sn); //Just needed to discover SN[8]
    CHECK_STATUS(status);
    uint8_t mode = (1 << 0);
    uint8_t nonce[32] = {0};
    uint8_t response[32] = {0};
    uint8_t zero[20] = {0}; //was 32 brad

    status = atcab_nonce_rand(zero, nonce);
    CHECK_STATUS(status);
    //Step 2.2
    //build mac
    struct atca_temp_key temp_key;
    struct atca_nonce_in_out nonce_host;
    nonce_host.zero = NONCE_ZERO_CALC_RANDOM; //0x0000
    nonce_host.mode = NONCE_MODE_SEED_UPDATE; //0x00
    nonce_host.num_in = zero;
    nonce_host.rand_out = nonce;
    nonce_host.temp_key = &temp_key;
    status = atcah_nonce(&nonce_host); //MCU only calc
    CHECK_STATUS(status);
    //printf("Calculated Tempkey:\n"); print_hex_string(nonce_host.temp_key->value, 32);
    //Step 2.3
    struct atca_mac_in_out param;
    param.challenge = NULL;
    param.key = key;
    param.key_id = (uint16_t) slot;
    param.mode = mode;
    param.temp_key = &temp_key;
    param.response = response;
    param.sn = sn;
    param.otp = NULL;
    status = atcah_mac(&param);
    CHECK_STATUS(status);
    //printf("Calculated MAC\n"); print_hex_string(response, 32);
    //Step 2.4
    uint8_t otherdata[CHECKMAC_OTHER_DATA_SIZE] = {0};
    otherdata[0] = 0x08; //match to mac command byte opp code
    otherdata[1] = mode; // match to mac mode
    otherdata[2] = slot;
    otherdata[3] = 0x00;
    otherdata[7] = 0x00;
    otherdata[8] = 0x00;
    otherdata[9] = 0x00;
    otherdata[10] = 0x00;
    otherdata[11] = 0x00;
    otherdata[12] = 0x00;
    status = atcab_checkmac(mode,
            (uint16_t) slot,
            NULL,
            response,
            otherdata);
    if (status == ATCA_SUCCESS) {
        printf("Slot %d Authenticated\n\n", slot);
        return 1;
    } else {
        printf("Failed to authenticate slot %d\n\n", slot);
        return 0;
    }
}

void SECURE_ELEMENT_SetLimit(uint32_t * limit) {

    uint8_t mac[32] = {0};
    SECURE_ELEMENT_SlotAuth(2, mcu_key);
    uint8_t slot_bytes[32] = {0};
    slot_bytes[0] = limit[0] & 0xfe;
    slot_bytes[1] = limit[1];
    slot_bytes[2] = limit[2];
    slot_bytes[3] = limit[3];
    slot_bytes[4] = limit[0] & 0xfe;
    slot_bytes[5] = limit[1];
    slot_bytes[6] = limit[2];
    slot_bytes[7] = limit[3];
    ATCA_STATUS status = atcab_write_enc(3, 0, slot_bytes, disk_key, 0, mac);
    CHECK_STATUS(status);
    printf("Set new limit: %lu\n", *limit);

}
