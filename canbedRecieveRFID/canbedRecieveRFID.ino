// receive a frame from can bus

#include <SPI.h>
#include "mcp_can.h"

const int SPI_CS_PIN = 17;              // CANBed V1
// const int SPI_CS_PIN = 3;            // CANBed M0
// const int SPI_CS_PIN = 9;            // CAN Bus Shield

MCP_CAN CAN(SPI_CS_PIN);                                    // Set CS pin

unsigned char message[94];
int index = 0;
String finalMessage = "";
void setup()
{
    Serial.begin(115200);
    while (CAN_OK != CAN.begin(CAN_1000KBPS))    // init can bus : baudrate = 500k
    {
        Serial.println("CAN BUS FAIL!");
        delay(100);
    }
    Serial.println("CAN BUS OK!");
}


void loop()
{
  unsigned char len = 0;
  unsigned char buf[8];

    if(CAN_MSGAVAIL == CAN.checkReceive())            // check if data coming
    {
      bool eot = false;
      CAN.readMsgBuf(&len, buf);    // read data,  len: data length, buf: data buf
      if (buf[0] & 0x80 == 0x80){
        eot = true;
      }
      buf[0] = buf[0] & 0x7F; // Removes more to come bit

      unsigned long canId = CAN.getCanId();
      
      Serial.println("-----------------------------");
      Serial.print("Get data from ID: ");
      Serial.println(canId, HEX);
      for (int i = 0; i < 8; i++){
        if (buf[i] != 0x0) {
          message[index] = buf[i];
          Serial.print((char)message[index]);
          Serial.print(" ");
          index++;
        }
        else {
          break;
        }
      }
      if (eot) {
        for (int i = 0; i < index; i++) {
          finalMessage += ((char) message[i]);
        }
        Serial.println("");
        Serial.println(finalMessage);
      }
        
    }
}

/*********************************************************************************************************
  END FILE
*********************************************************************************************************/
