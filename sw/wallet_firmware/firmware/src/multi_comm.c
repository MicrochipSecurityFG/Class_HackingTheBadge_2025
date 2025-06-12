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
#include <stdlib.h> 
#include "multi_comm.h"
#include "util.h"

extern rx_t rx;

uint8_t MULTI_COMM_ReadByte(bool* isUART) {

    if (ir_packet.valid_packet == true) {
        if (ir_packet.data_index == ir_packet.length) {
            ir_packet.data_index = 0;
        }
        if (ir_packet.data_index == ir_packet.length - 2) {
            ir_packet.valid_packet = false;
            return LINE_FEED;
        }
        if (isUART != NULL) {
            *isUART = false;
        }
        return ir_packet.buffer[ir_packet.data_index++];
    } else {
        if (isUART != NULL) {
            *isUART = true;
        }
        return SERCOM5_USART_ReadByte();
    }
}

bool MULTI_COMM_GetLine(char* buffer, size_t max_len) {
    uint8_t i = 0;
    char input_char = 0;
    memset(buffer, 0, max_len);
    while (i < max_len - 1) {
        while (!MULTI_COMM_ReceiverIsReady());
        input_char = MULTI_COMM_ReadByte(NULL);
        i++;
        if (input_char == '\n' || input_char == '\r') {
            buffer[i - 1] = '\0';
            //printf("Got newline, buffer='%s'\n", buffer);
            return true;
        }
        buffer[i - 1] = input_char;
    }
    buffer[i] = '\0';
    return false;
}

bool MULTI_COMM_ReceiverIsReady() {

    if (SERCOM5_USART_ReceiverIsReady() || ir_packet.valid_packet == true) {
        return true;
    } else {
        return false;
    }
}

uint8_t MULTI_COMM_GetUserInput(uint8_t menuModeFlag) {
    uint8_t u8_index = 0;
    {
        //Receive data until 30 bytes received, line feed or carriage return
        if (SERCOM5_USART_ReceiverIsReady()) {

            rx.receiveBuffer[rx.receivedCount] = SERCOM5_USART_ReadByte();

            if (rx.receiveBuffer[rx.receivedCount] != LINE_FEED) rx.receivedCount++;
            
            if (menuModeFlag || rx.receiveBuffer[rx.receivedCount] == LINE_FEED) {
                rx.receiveBuffer[rx.receivedCount] = 0x00; // end string with null
                u8_index = rx.receivedCount;
                rx.receivedCount = 0;
                return u8_index;
                //break;
            } else {
                if (rx.receivedCount >= 48) {
                    u8_index = rx.receivedCount;
                    rx.receivedCount = 0;
                    return u8_index;
                }
            }
        }
        if (ir_packet.valid_packet == true) {
            //copy packet to receive buffer
            memcpy(rx.receiveBuffer, ir_packet.buffer, ir_packet.length - 2);
            rx.receiveBuffer[ir_packet.length - 2] = 0x00; //string terminator
            ir_packet.valid_packet = false;
            return ir_packet.length - 2;
            // break;
        }
        return 0;
    }
}

void MULTI_COMM_Print(const char *str, bool outputSerial) {

    //Send over IR
    ir_packet.info_byte = 0x00;
    memset(ir_packet.buffer, 0x00, sizeof (ir_packet.buffer)); //Clear buffer to protect null string terminators
    memcpy(ir_packet.buffer, str, strlen(str));
    ir_packet.data_index = strlen(str);
    ir_packet.length = (uint16_t) strlen(str) + 3;
    ir_packet.crc = UTIL_crc16_CCITT(ir_packet.buffer, strlen(str));
    ir_packet.buffer[ir_packet.data_index++] = (uint8_t) (ir_packet.crc >> 8);
    ir_packet.buffer[ir_packet.data_index++] = (uint8_t) (ir_packet.crc);
    IR_SendPacket(&ir_packet);

    // Print the string using printf
    if (outputSerial == true) {
        printf("%s", str);
    }
}

/* *****************************************************************************
 End of File
 */
