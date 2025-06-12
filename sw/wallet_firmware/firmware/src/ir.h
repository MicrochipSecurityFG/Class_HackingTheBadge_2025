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

#ifndef _IR_H    /* Guard against multiple inclusion */
#define _IR_H

#define UART_RX_BUFFER_SIZE 350
#include "config/default/definitions.h"


typedef enum {
    WAITING_FOR_BREAK,
    WAITING_FOR_SYNC,
    RECEIVING_DATA,
    RECEIVING_CONTROL_BYTE,
    RECEIVING_LENGTH_BYTE,
    RECEIVING_CRC
} uart_state_t;

typedef struct {
    uint8_t buffer[UART_RX_BUFFER_SIZE];
    uint16_t crc;
    uint16_t length;
    uint8_t info_byte;
    uart_state_t state;
    uint16_t data_index;
    bool valid_packet;
} ir_packet_t;


bool IR_SendMessage(const char *str, int8_t retry_count, const char *expected_response);
void IR_Send(uint8_t byte);
void IR_CheckTimeOut();
void IR_EnableReceive();
void ir_test(char * input);
void IR_Receive(uintptr_t event);
void IR_SendPacket(ir_packet_t * packet); 
void IR_FlushReceiver(void);

#define AES_BLOCK_SIZE 16
#define LINE_FEED 0x0a

// Step Password 3.4.1
typedef struct rx {
    uint8_t receivedCount;
    uint8_t receiveBuffer[128];
    bool HideAdminMode;
} rx_t;

#define DELAY_TIME 417

extern uint32_t ir_power;
extern uint32_t ir_power;
extern ir_packet_t ir_packet;



#endif /* _IR_H */

/* *****************************************************************************
 End of File
 */
