/* ************************************************************************** */
/** Descriptive File Name

  @Company
    Company Name

  @File Name
    filename.h

  @Summary
    Brief description of the file.

  @Description
    Describe the purpose of this file.
 */
/* ************************************************************************** */

#ifndef _UTIL_H    /* Guard against multiple inclusion */
#define _UTIL_H

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include <stdint.h>

#define CHECK_STATUS(s)                                                 			\
if(s != ATCA_SUCCESS)                                                   			\
{                                                                       			\
	printf("Error: Line %d in %s\n", __LINE__, __FILE__);                           \
    	printf("STATUS = %X\n", s);                                       			\
    	printf("Code explanations can be found in atca_status.h \n\n");             \
    	while(1);                                                           		\
}

uint16_t UTIL_crc16_CCITT(uint8_t *data, size_t length);

void UTIL_ShiftLeft(unsigned char* array, size_t length);

bool UTIL_StringContains(const char *str, const char *substr);

void UTIL_PrintArray(uint8_t * ptr, uint16_t length);

void UTIL_HexToBuffer(uint8_t *dest, uint8_t *src, uint16_t length);

void UTIL_PrintHexString(uint8_t * ptr, uint16_t length);

void UTIL_PrintHexPlusASCII(const uint8_t* buffer, size_t length, unsigned int start_address);

#define _ir_rx_disable() PWM_Clear();
#define _ir_rx_enable() PWM_Set();

#define MAIN_MENU_ACTIVE_LED() PWM_Set();

#endif /* _UTIL_H */

/* *****************************************************************************
 End of File
 */
