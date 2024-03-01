#include <SPI.h>
#include <MFRC522.h>
#include <mcp_can.h>

#define RST_PIN         9           // Configurable, see typical pin layout above
#define SS_PIN          10          // Configurable, see typical pin layout above

#define CAN_CS_PIN      17


MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

byte buffer[18];
byte block;
byte input[64][16];
byte finalArray[47][16];
MFRC522::StatusCode status;


bool readCard = false;
    
MFRC522::MIFARE_Key key;

MCP_CAN CAN(CAN_CS_PIN);                                    // Set CS pin

// Number of known default keys (hard-coded)
// NOTE: Synchronize the NR_KNOWN_KEYS define with the defaultKeys[] array
#define NR_KNOWN_KEYS   8
byte knownKeys[NR_KNOWN_KEYS][MFRC522::MF_KEY_SIZE] =  {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);         // Initialize serial communications with the PC
  while (!Serial);            // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();                // Init SPI bus
  mfrc522.PCD_Init();         // Init MFRC522 card
  for (byte i = 0; i < 6; i++) {
    key.keyByte[i] = 0xFF;
  }
  while (CAN_OK != CAN.begin(CAN_1000KBPS))    // init can bus : baudrate = 500k
    {
      Serial.println("CAN BUS FAIL!");
      delay(100);
    }
    Serial.println("CAN BUS OK!");
}

void dump_byte_array_hex(byte *buffer, byte bufferSize) { // Can be removed after testing
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

void dump_byte_array_ASCII(byte *buffer, byte bufferSize) { // Can be removed after testing
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.write(buffer[i]);
  }
}

bool try_key(MFRC522::MIFARE_Key *key)
{
  bool result = false;
    
  for(byte block = 0; block < 64; block++){
      
    // Serial.println(F("Authenticating using key A..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("PCD_Authenticate() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }

    // Read block
    byte byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(block, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    }
    else {
      // Successful read
      result = true;
      Serial.print(F("Success with key:"));
      dump_byte_array_hex((*key).keyByte, MFRC522::MF_KEY_SIZE);
      Serial.println();
      
      // Dump block data
      Serial.print(F("Block ")); Serial.print(block); Serial.print(F(":"));
      dump_byte_array_ASCII(buffer, 16); //omzetten van hex naar ASCI
      Serial.println();
      
      for (int p = 0; p < 16; p++) //De 16 bits uit de block uitlezen
      {
        input[block][p] = buffer[p];
        Serial.print(input[block][p]);
        Serial.print(" ");
      }
    }
  }
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  return result;
}

void loop() {
  // put your main code here, to run repeatedly:
  while (!readCard) {
    readCard = ReadCard();
    delay(100);
  }
  //filter
  filterInput();
  Serial.println("");
  for (int i = 0; i < 47; i++) {
    Serial.print("Block ");
    Serial.print(i);
    Serial.print(": ");
    for (int j = 0; j < 16; j++) {
      Serial.print((char) finalArray[i][j]);
      Serial.print(" ");
    }
    Serial.println("");
  }
  //Send over Can
  transmit();

  //Reset & allow a new rfid read eventually
  for (int i = 0; i < 64; i++) {
    for (int j = 0; j < 16; j++) {
      input[i][j] = 0x0;
    }
  }
  for (int i = 0; i < 47; i++) {
    for (int j = 0; j < 16; j++) {
      finalArray[i][j] = 0x0;
    }
  }
  readCard = false;
  delay(10000);
}

bool ReadCard(){ //Read card
  Serial.println("Insert card...");
  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return false;
  }
  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return false;
  }

  // Show some details of the PICC (that is: the tag/card)
  //Serial.print(F("Card UID:"));
  dump_byte_array_hex(mfrc522.uid.uidByte, mfrc522.uid.size);
  //Serial.println();
  //Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  //Serial.println(mfrc522.PICC_GetTypeName(piccType));
  
  // Try the known default keys
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    key.keyByte[i] = knownKeys[0][i];
    // Try the key
    if (try_key(&key)) {
      // Found and reported on the key and block,
      // no need to try other keys for this PICC
      return true;
    }
  }
}

void filterInput() {
  int currentIndex = 0;
  int currentByteIndex = 0;
  for (int block = 1; block < 64; block++) { //Steps through blocks
    if (block%4 == 3){ //Not writable data, can be discarded
      continue;
    }
    for (int currentByte = 0; currentByte < 16; currentByte++) {
      if (input[block][currentByte] != 0x0) { //Null can be discarded
        finalArray[currentIndex][currentByteIndex] = input[block][currentByte];
        currentByteIndex++;
        if (currentByteIndex == 16) {
          currentByteIndex = 0;
          currentIndex++;
        }
      }
    }
  }
  if (currentIndex != 46 && currentByteIndex != 15) {
    while(currentIndex != 46 && currentByteIndex != 15) {
      finalArray[currentIndex][currentByteIndex] = 0x0;
      currentByteIndex++;
      if (currentByteIndex == 16){
        currentIndex++;
        currentByteIndex = 0;
      }
    }
  }
}

void transmit() {
  //Will read and transmit all non \0 bytes
  Serial.println("transmitting");
  bool last = false;
  unsigned char canMsg[8];
  int currentCanIndex = 0;
  for (int block = 0; block < 47; block++) { //Step through each block
    if (last) { //No more messages need to be sent
      Serial.println("EOT");
      break;
    }
    for (int index = 0; index < 16; index++) { //Step through each index
      if(finalArray[block][index] == 0x0) {
        last = true;
        Serial.println("Last transmission");
      }
      canMsg[currentCanIndex] = finalArray[block][index];
      currentCanIndex++;
      if(currentCanIndex == 8) {
        currentCanIndex = 0;
        if (last == false) {
          canMsg[0] = canMsg[0] | 0x80; // Adds a one the 128th bit position as a flag for more to come
          Serial.println(canMsg[0], HEX);
        }
        Serial.println("Transmitting");
        for (int i = 0; i <8; i++) {
          Serial.print((char)canMsg[i]);
          Serial.print(" ");
        }
        Serial.println("End of Transmission");
        CAN.sendMsgBuf(0x09, 0, 8, canMsg);
        delay(100);      // send data per 50ms
        if(last) {
          break;
        }
      }
    }
  }
}
