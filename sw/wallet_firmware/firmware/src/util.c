/* ************************************************************************** */
/** Descriptive File Name

  @Company
    Company Name

  @File Name
    filename.c

  @Summary
    Brief description of the file.

  @Description
    Describe the purpose of this file.
 */
#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include <stdio.h>
#include <ctype.h>
#include "util.h"

uint16_t UTIL_crc16_CCITT(uint8_t *data, size_t length) {
    uint16_t crc = 0xFFFF; // Initial value
    uint16_t polynomial = 0x1021; // Polynomial for CRC-CCITT

    for (size_t i = 0; i < length; i++) {
        crc ^= (uint16_t) data[i] << 8; // Input is shifted left by 8 bits
        for (int j = 0; j < 8; j++) { // Process each bit
            if (crc & 0x8000)
                crc = (crc << 1) ^ polynomial;
            else
                crc <<= 1;
        }
    }
    //printf("&\n");

    return crc; // Return the final CRC value
}

void UTIL_ShiftLeft(unsigned char* array, size_t length) {
    if (length == 0) {
        return;
    }

    for (size_t i = 0; i < length - 1; i++) {
        array[i] = array[i + 1];
    }

    // Optionally, you can set the last element to 0 or another value
    array[length - 1] = 0;
}

bool UTIL_StringContains(const char *str, const char *substr) {
    if (!*substr) {
        return true; // An empty substring is always found
    }

    while (*str) {
        const char *start = str;
        const char *pattern = substr;

        // Check if the substring matches starting from the current position
        while (*str && *pattern && *str == *pattern) {
            str++;
            pattern++;
        }

        if (!*pattern) {
            return true; // Found the substring
        }

        str = start + 1; // Move to the next character in the main string
    }

    return false; // Substring not found
}

void UTIL_PrintArray(uint8_t * ptr, uint16_t length) {
    uint16_t i = 0;
    uint8_t line_count = 0;
    for (; i < length; i++) {
        printf("0x%02x, ", ptr[i]);
        line_count++;
        if (line_count == 8) {
            printf("\n");
            line_count = 0;
        }
    }
    printf("\n");
}

void UTIL_HexToBuffer(uint8_t *dest, uint8_t *src, uint16_t length) {
    uint16_t i = 0;
    uint16_t j = 0;
    for (; i < length; i++) {
        // Print each byte as hex to stdout, just for confirmation or logging
        //printf("%02x", src[i]);

        // Correctly use snprintf to write into the buffer without adding a null terminator within the hex data
        snprintf((char *) &dest[j], 3, "%02x", src[i]);
        j += 2; // Move past the two hex characters written
    }

    //printf("%s", dest);
}

void UTIL_PrintHexString(uint8_t * ptr, uint16_t length) {
    uint16_t i = 0;
    //uint8_t line_count = 0;
    for (i = 0; i < length; i++) {
        printf("%02x", ptr[i]);

    }
    printf("\n");
}

void UTIL_PrintHexPlusASCII(const uint8_t* buffer, size_t length, unsigned int start_address) {
    for (size_t i = 0; i < length; i += 16) { // Process 16 bytes per line
        // Print the address
        printf("%08X: ", start_address + (unsigned int)(i));

        // Print the bytes in hex
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < length) {
                printf("%02X ", buffer[i + j]);
            } else {
                printf("   "); // Fill the gap with spaces if the buffer size is not a multiple of 16
            }
        }

        // Print the ASCII representation
        printf(" ");
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < length) {
                uint8_t byte = buffer[i + j];
                printf("%c", isprint(byte) ? byte : '.');
            }
        }
        printf("\n");
    }
}

/* *****************************************************************************
 End of File
 */
