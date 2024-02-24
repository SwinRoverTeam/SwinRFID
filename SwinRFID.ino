#include <SPI.h>
#include "mcp_canbus.h"

#include <MFRC522.h>


/**
 * The RFID card contains 64 blocks of 16 hexadecimal bytes.
 * Block 0 contains manufacturer data
 * Every fourth Block (3, 7, 11, and so on) are sector trailers which contain access
  bits for read and write access to the remaining three Blocks in that sector.
  *There are 47 Blocks which can be altered on the RFID card to encode a string of text as
  a message.
 * The status readout message can be obtained by concatenating the data in
  each of the alterable Blocks, in ascending order (Blocks 1, 2, 4, and so on).
 */

// A.1.6.1. The access bits for all sectors will be the factory default: FF 07 80.
// A.1.6.2. The authentication key will be the factory default: 0xFFFF FFFF FFFF.
// A.1.6.3. The status readout message may not necessarily begin at the first alterable
// block, and !!!may have null blocks in between blocks containing the message!!!.

//challenge config

const int SECTOR_COUNT = 16;
const int VALUE_BLOCK_A = 1;
const int VALUE_BLOCK_B = 2;
const int TRAILER_BLOCK = 3;
//constants
const int SPI_CS_PIN = 17;
const int RESET_PIN = 5;
const unsigned char CANBED_ID = 0x09;
//filters
const unsigned char REC_FILTER_ID = 0x04;
const unsigned char SEND_FILTER_ID = 0x05;

#define RST_PIN         RESET_PIN         
#define SS_PIN          10

MFRC522 mfrc522(SS_PIN, RST_PIN); 
MFRC522::MIFARE_Key key;

MCP_CAN CAN(SPI_CS_PIN); 

void setup() {
  Serial.begin(115200);
  while (CAN_OK != CAN.begin(CAN_1000KBPS))    // init can bus : baudrate = 1000k
  {
    Serial.println("CAN BUS FAIL!");
    delay(100);
  }
  Serial.println("CAN BUS OK!");
  SPI.begin();
  mfrc522.PCD_Init();

  // A.1.6.2. The authentication key will be the factory default: 0xFFFF FFFF FFFF.
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }

  // Serial.println(F("Scan a MIFARE Classic PICC to demonstrate read and write."));
  // Serial.print(F("Using key (for A and B):"));
  // dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
  // Serial.println();

  // Serial.println(F("BEWARE: Data will be written to the PICC, in sector #1"));


}

void loop() {
  if ( ! mfrc522.PICC_IsNewCardPresent())
      return;

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial())
      return;

  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));

  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  unsigned char msg[4][8];
  int m = 0;
  int c = 0;
  //  * The RFID card contains 64 blocks of 16 hexadecimal bytes.
  for(int i = 0; i < SECTOR_COUNT; i++) {
    byte sector = i;
    byte valueBlockA = i*4+VALUE_BLOCK_A;
    byte valueBlockB = i*4+VALUE_BLOCK_B;
    // Every fourth Block (3, 7, 11, and so on) are sector trailers which contain access
    byte trailerBlock = i*4+TRAILER_BLOCK;
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    int32_t value;

    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
  

    // Show the whole sector as it currently is
    Serial.println(F("Current data in sector:"));
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();

    byte trailerBuffer[] = {
          255, 255, 255, 255, 255, 255,       // Keep default key A
          0, 0, 0,
          0,
          255, 255, 255, 255, 255, 255};      // Keep default key B
    mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 0, 6, 6, 3);

    Serial.println(F("Reading sector trailer..."));
    status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Check if it matches the desired access pattern already;
    // because if it does, we don't need to write it again...
    if (    buffer[6] != trailerBuffer[6]
        ||  buffer[7] != trailerBuffer[7]
        ||  buffer[8] != trailerBuffer[8]) {
        // They don't match (yet), so write it to the PICC
        Serial.println(F("Writing new sector trailer..."));
        status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("MIFARE_Write() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
            return;
        }
    }

        // Authenticate using key B
    Serial.println(F("Authenticating again using key B..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    formatValueBlock(valueBlockA);
    formatValueBlock(valueBlockB);

    addByteToMessage(msg, m, c, valueBlockA);
    addByteToMessage(msg, m, c, valueBlockB);


  }
  for(int j = 0; j < 4; j++)
  {
    sendRFIDMessage(msg[j]);
  }
}

void addByteToMessage(unsigned char msg[][8], int &m, int &c, byte valueBlock){
  //null check
  if(valueBlock) {
    msg[m][c] = valueBlock;
  } else {
    msg[m][c] = 32;
  }
  c++;
  //8 bytes of data per CAN message
  if(c==8) {
    m++;
    c = 0;
  }
}

void sendRFIDMessage(unsigned char buf[8]) {
  CAN.sendMsgBuf(0x00, CANBED_ID, 8, buf);
}



/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

void formatValueBlock(byte blockAddr) {
    byte buffer[18];
    byte size = sizeof(buffer);
    MFRC522::StatusCode status;

    Serial.print(F("Reading block ")); Serial.println(blockAddr);
    status = mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    if (    (buffer[0] == (byte)~buffer[4])
        &&  (buffer[1] == (byte)~buffer[5])
        &&  (buffer[2] == (byte)~buffer[6])
        &&  (buffer[3] == (byte)~buffer[7])

        &&  (buffer[0] == buffer[8])
        &&  (buffer[1] == buffer[9])
        &&  (buffer[2] == buffer[10])
        &&  (buffer[3] == buffer[11])

        &&  (buffer[12] == (byte)~buffer[13])
        &&  (buffer[12] ==        buffer[14])
        &&  (buffer[12] == (byte)~buffer[15])) {
        Serial.println(F("Block has correct Value Block format."));
    }
    else {
        Serial.println(F("Formatting as Value Block..."));
        byte valueBlock[] = {
            0, 0, 0, 0,
            255, 255, 255, 255,
            0, 0, 0, 0,
            blockAddr, ~blockAddr, blockAddr, ~blockAddr };
        status = mfrc522.MIFARE_Write(blockAddr, valueBlock, 16);
        if (status != MFRC522::STATUS_OK) {
            Serial.print(F("MIFARE_Write() failed: "));
            Serial.println(mfrc522.GetStatusCodeName(status));
        }


    }
}
