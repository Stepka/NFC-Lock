
// RFID

#include <Wire.h>
#include <SPI.h>
// Here we use custom version of the Adafruit_PN532 lib
#include "Adafruit_PN532.h"

// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
#define PN532_IRQ   (2)
#define PN532_RESET (3)  // Not connected by default on the NFC Shield

// Or use this line for a breakout or shield with an I2C connection:
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);

uint8_t DEFAULT_KEY[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
byte UID_SIZE = 4;

// BUZZER

const int BUZZER = 4;

// CRYPTO

#include <AES.h>
AES128 aes128;

// PROTOCOL

// Custom protocol
// | type | data |
// type:
//      - response status (ok/error)
//      - command
// data:
//      - none for ok
//      - info for error
//      - action or data for commands

// type
const byte RFID_CHECK_AID_COMMAND = 0x00;
const byte RFID_GIVE_ACTION_COMMAND = 0x01;
const byte RFID_LOCK_SWITCHED = 0x02;
const byte RFID_ADD_KEY_COMMAND = 0x03;
const byte RFID_ADDING_KEY_CONFIRMED = 0x04;

const byte CARD_ERROR_RESPONSE = 0x00;
const byte CARD_OK_RESPONSE = 0x01;
const byte CARD_ACTION = 0x02;

// data
const byte ACTION_SWITCH_LOCK = 0x01;
// the response sent from the phone if it does not understand an APDU
const byte INFO_UNKNOWN_ERROR = 0xff;
const byte INFO_UNKNOWN_COMMAND = 0xfe;
const byte INFO_UNKNOWN_AID = 0xfd;
const byte INFO_TIMEOUT = 0xfc;
const byte INFO_NO_PIN = 0xfb;
byte AID_DATA[] = {
  //  0x00, /* CLA */
  0xA4, /* INS */
  0x04, /* P1  */
  0x00, /* P2  */
  0x06, /* Length of AID  */
  0xF0, 0xAB, 0xCD, 0xEF, 0x00, 0x00,
};

byte communication_state;
// states
const byte WAITING_FOR_A_CARD = 0x00;
const byte WAITING_FOR_ACTION = 0x01;
const byte SWITCHING_LOCK = 0x03;
const byte WAITING_FOR_PIN = 0x04;
const byte ADDING_AS_KEY = 0x05;
const byte SEND_ADDING_KEY_CONFIRMED = 0x06;

byte rfid_data[16];

// EEPROM

#include <EEPROM.h>

#define IS_LOCKED_ADDR (0)  // is locked var address
#define KEYS_DB_ADDR (1)

#define KEY_TYPE_ADMIN (0)
#define KEY_TYPE_MIFARE_CLASSIC (1)
#define KEY_TYPE_ANDROID (2)

struct KeyItem
{
  byte type;
  byte uid[7];
  byte key_A[16];
  byte key_B[6];
  byte sector;
};

KeyItem keys[5];
byte num_keys = 0;

byte locked = 1;

// TIMER

#include "GyverTimer.h"

GTimer reset_timer(MS);

// STATE

#define STATE_INIT (0)
#define STATE_LOCK (1)
#define STATE_ADMIN (2)

byte lock_state = STATE_INIT;

//

void setup() {

  digitalWrite(12, HIGH);
  delay(200);

  Serial.begin(9600);

  randomSeed(analogRead(0));

  pinMode(9, OUTPUT);
  pinMode(10, OUTPUT);
  pinMode(11, OUTPUT);
  pinMode(12, OUTPUT);
  pinMode(13, OUTPUT);
  pinMode(A0, INPUT_PULLUP);
  pinMode(A1, INPUT_PULLUP);
  pinMode(A2, OUTPUT);
  pinMode(A3, OUTPUT);

  pinMode(BUZZER, OUTPUT);

  noTone(BUZZER);

  // NFC

  nfc.begin();

  Serial.print("Srart...");

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
    Serial.print("Didn't find PN53x board");
    while (1); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata >> 24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata >> 8) & 0xFF, DEC);

  // configure board to read RFID tags
  nfc.SAMConfig();

  //
  //
  locked = EEPROM.read(IS_LOCKED_ADDR);
  if (locked > 0) locked = 1;
  digitalWrite(13, locked);
  //
  //    byte db_pointer = KEYS_DB_ADDR;
  //    EEPROM.write(db_pointer, 0);
  //    write_keys_db();

  read_keys_db();


  if (num_keys == 0) {
    switch_state(STATE_INIT);
  }
  else
  {
    switch_state(STATE_LOCK);
  }

  //

  if (lock_state == STATE_INIT)
  {
    admin_mode_start_beep();
    admin_mode_end_beep();
  }
  else
  {
    ready_beep();
  }

  //  Serial.println("Waiting for a card...");

  reset_timer.setTimeout(190080000); // reset after 24 hours
}

void loop() {

  if (reset_timer.isReady()) {
    digitalWrite(12, LOW);
  }

  KeyItem key;
  boolean known_key_found;
  uint8_t success;
  communication_state = WAITING_FOR_A_CARD;

  //  Serial.println("Listening...");
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  if (nfc.inListPassiveTarget(uid, &uidLength)) {

    if (uidLength != UID_SIZE)
    {
      //      Serial.println("UID size not supported");
      return;
    }

    if (lock_state == STATE_INIT) {
      Serial.println("There are no admin keys, adding new one...");
      success = add_admin_key(uid);
      if (success)
      {
        admin_mode_start_beep();
        admin_mode_end_beep();
        Serial.println("Admin key added");
        switch_state(STATE_LOCK);
      }
      else
      {
        error_beep();
      }
      delay(1000);
    }
    else
    {
      known_key_found = false;
      for (byte i = 0; i < num_keys; i++) {
        //        Serial.println("Checking...");
        //        nfc.PrintHex(uid, UID_SIZE);
        //        nfc.PrintHex(keys[i].uid, UID_SIZE);
        if (memcmp(uid, keys[i].uid, UID_SIZE) == 0)
        {
          key = keys[i];
          known_key_found = true;
          break;
        }
      }
      if (known_key_found)
      {
        if (key.type == KEY_TYPE_ADMIN)
        {
          //          Serial.println("It is known admin mifare card");
          success = read_nfc_tag(uid, key.key_A, key.sector);
          if (success)
          {
            switch (lock_state) {

              case STATE_LOCK:
                switch_state(STATE_ADMIN);
                break;

              case STATE_ADMIN:
                error_beep();
                switch_state(STATE_LOCK);
                //                Serial.println("It is known mifare card, we do not need to add it again");
            }
            delay(1000);
          }
        }
        else if (key.type == KEY_TYPE_MIFARE_CLASSIC)
        {
          //          Serial.println("It is known mifare card");
          switch (lock_state) {

            case STATE_LOCK:
              success = read_nfc_tag(uid, key.key_A, key.sector);
              if (success)
              {
                switch_lock();
                ready_beep();
                delay(1000);
              }
              else
              {
                error_beep();
              }
              break;

            case STATE_ADMIN:
              //              Serial.println("It is known mifare card, we do not need to add it again");
              error_beep();
              break;
          }
          switch_state(STATE_LOCK);
        }
        else
        {
          //          Serial.println("It is android");
          switch (lock_state) {

            case STATE_LOCK:
              read_nfc_android(key.uid, key.key_A);
              break;

            case STATE_ADMIN:
              //              Serial.println("It is known android mobile, rewrite key");
              remove_key(key);
              read_nfc_android(key.uid, key.key_A);
              break;
          }
          switch_state(STATE_LOCK);
        }
      }
      else
      {
        //        Serial.println("It is unknown object");
        switch (lock_state) {

          case STATE_ADMIN:
            success = read_nfc_android(uid, NULL);
            if (success)
            {
              Serial.println("New android device added");
            }
            else
            {
              success = add_card_key(uid);
              if (success)
              {
                Serial.println("New card added");
              }
              else
              {
                error_beep();
              }
            }
            switch_state(STATE_LOCK);
            delay(1000);
            break;

          default:
            error_beep();
            delay(1000);
        }
      }
    }
  }
  else {
    //    Serial.print("Trying again...");
  }

  //  Serial.println("Waiting for a card...");
}

void send_command(byte command, byte* data, uint8_t dataLength, byte *response) {
  byte sendingData[32];
  sendingData[0] = command;
  for (byte j = 0; j < dataLength; j++) {
    sendingData[j + 1] = data[j];
  }

  uint8_t responseLength = 32;
  if (dataLength <= 0) {
    // we cannot send 1 byte, so just add some salt at the end
    sendingData[1] = 0xff;
    dataLength = 1;
  }

  if (nfc.inDataExchange(sendingData, dataLength + 1, response, &responseLength)) {
    if (responseLength > 0) {
      return;
    }
  }

  // unknown error
  response[0] = CARD_ERROR_RESPONSE;
  response[1] = INFO_TIMEOUT;
}

void communicate(byte *response) {
  switch (communication_state) {

    case WAITING_FOR_A_CARD:
      send_command(RFID_CHECK_AID_COMMAND, AID_DATA, sizeof(AID_DATA), response);
      break;

    case ADDING_AS_KEY:
      for (byte i = 0; i < 16; i++) {
        rfid_data[i] = random(255);
      }
      //      Serial.println("Send key.");
      //      nfc.PrintHex(rfid_data, 16);
      send_command(RFID_ADD_KEY_COMMAND, rfid_data, 16, response);
      break;

    case WAITING_FOR_ACTION:
      for (byte i = 0; i < 16; i++) {
        rfid_data[i] = random(255);
      }

      send_command(RFID_GIVE_ACTION_COMMAND, rfid_data, 16, response);
      break;

    case SWITCHING_LOCK:
      send_command(RFID_LOCK_SWITCHED, NULL, 0, response);
      break;

    case SEND_ADDING_KEY_CONFIRMED:
      send_command(RFID_ADDING_KEY_CONFIRMED, NULL, 0, response);
      break;
  }
}

boolean read_nfc_tag(byte* uid, byte* keya, uint8_t sector) {
  uint8_t block = 0;
  uint8_t success;

  success = nfc.mifareclassic_AuthenticateBlock(uid, UID_SIZE, sector * 4 + block, 0, keya);

  if (success)
  {
  }
  else
  {
    //    Serial.println("read_nfc_tag: Auth failed");
    return false;
  }

  return true;
}

uint8_t write_nfc_tag(byte* uid, byte* keya, byte* keyb) {
  uint8_t success = false;
  // 0 is ot valid sector
  uint8_t sector = 0;
  uint8_t uidLength;

  for (uint8_t i = 1; i < 15; i++)
  {
    success = read_nfc_tag(uid, DEFAULT_KEY, i);
    if (success)
    {
      sector = i;
      break;
    }
    else
    {
      nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
    }
  }

  if (success)
  {
    uint8_t access_bits[4] = { 0x78, 0x77, 0x88, 0xFF };
    uint8_t newkeys[16];
    for (uint8_t i = 0; i < 6; i++)
    {
      newkeys[i] = keya[i];
    }
    for (uint8_t i = 0; i < 4; i++)
    {
      newkeys[6 + i] = access_bits[i];
    }
    for (uint8_t i = 0; i < 6; i++)
    {
      newkeys[10 + i] = keyb[i];
    }
    success = nfc.mifareclassic_WriteDataBlock (sector * 4 + 3, newkeys);

    if (success)
    {
      //      dump_byte_array(newkeys, 16);
      //      Serial.println("");
      //      Serial.println("write succesful");
    }
    else
    {
      //      Serial.println("Ooops ... unable to write the requested block.  Try another key?");
    }
  }

  return sector;
}

boolean read_nfc_android(byte* uid, byte* keya) {
  byte responseData[32];

  while (true) {
    communicate(responseData);
    byte type = responseData[0];
    byte single_data;
    switch (type) {
      case CARD_OK_RESPONSE:
        switch (communication_state) {
          case WAITING_FOR_A_CARD:
            switch (lock_state) {

              case STATE_ADMIN:
                communication_state = ADDING_AS_KEY;
                wait_beep();
                break;

              case STATE_LOCK:
                communication_state = WAITING_FOR_ACTION;
                wait_beep();
                break;

              default:
                communication_state = WAITING_FOR_A_CARD;
            }
            break;

          case SWITCHING_LOCK:
            communication_state = WAITING_FOR_A_CARD;
            return true;

          case ADDING_AS_KEY:
            byte buffer[16];
            for (byte j = 0; j < 16; j++) {
              buffer[j] = responseData[j + 1];
            }
            if (memcmp(buffer, rfid_data, 16) == 0) {
              KeyItem lock_key = {
                .type = KEY_TYPE_ANDROID,
                .uid = {},
                .key_A = {},
                .key_B = {},
                .sector = 0
              };
              for (byte i = 0; i < UID_SIZE; i++) {
                lock_key.uid[i] = uid[i];
              }
              for (byte i = 0; i < 16; i++) {
                lock_key.key_A[i] = rfid_data[i];
              }

              boolean success = add_key(lock_key);
              if (success)
              {
                communication_state = SEND_ADDING_KEY_CONFIRMED;
                //                Serial.println("Key confirmed");
              }
            }
            else
            {
              //              Serial.println("Key not confirmed");
              error_beep();
            }
            break;

          case SEND_ADDING_KEY_CONFIRMED:
            communication_state = WAITING_FOR_A_CARD;
            return true;

          default:
            communication_state = WAITING_FOR_A_CARD;
        }
        break;

      case CARD_ERROR_RESPONSE:
        single_data = responseData[1];
        switch (single_data) {
          case INFO_NO_PIN:
            //            Serial.println("No PIN");
            communication_state = WAITING_FOR_PIN;
            break;
          case INFO_TIMEOUT:
            communication_state = WAITING_FOR_A_CARD;
            break;
          default:
            //                    Serial.println("Error!");
            error_beep();
            communication_state = WAITING_FOR_A_CARD;
        }
        communication_state = WAITING_FOR_A_CARD;
        break;

      case CARD_ACTION:

        byte encrypted_str[16];
        byte buffer[16];
        for (byte j = 0; j < 16; j++) {
          encrypted_str[j] = responseData[j + 1];
        }

        aes128.setKey(keya, aes128.keySize());
        aes128.decryptBlock(buffer, encrypted_str);
        //        Serial.println("key | got encrypted | decrypted");
        //        nfc.PrintHex(keya, 16);
        //        nfc.PrintHex(encrypted_str, 16);
        //        nfc.PrintHex(buffer, 16);
        //        Serial.println("");
        if (memcmp(buffer, rfid_data, 16) == 0) {

          single_data = responseData[16 + 1];
          switch (single_data) {
            case ACTION_SWITCH_LOCK:
              communication_state = SWITCHING_LOCK;
              switch_lock();
              ready_beep();
              break;
            default:
              //                      Serial.print("Unknown action: ");
              //                      Serial.println(single_data, HEX);
              communication_state = WAITING_FOR_A_CARD;
              error_beep();
          }
        }
        else {
          //                  Serial.println("Auth failed");
          error_beep();
        }
        break;


      default:
        //        Serial.print("Unknown response: ");
        //        Serial.println(type, HEX);
        communication_state = WAITING_FOR_A_CARD;
        error_beep();
    }

    if (communication_state == WAITING_FOR_A_CARD)
    {
      return false;
    }

    if (communication_state == WAITING_FOR_PIN)
    {
      communication_state = WAITING_FOR_A_CARD;
    }
  }
}


/**
   Helper routine to dump a byte array as hex values to Serial.
*/
//void dump_byte_array(byte * buffer, byte bufferSize) {
//  for (byte i = 0; i < bufferSize; i++) {
//    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
//    Serial.print(buffer[i], HEX);
//  }
//}

void ready_beep () {

  tone(BUZZER, 400);
  delay(100);
  tone(BUZZER, 2400);
  delay(100);
  noTone(BUZZER);
}

void wait_beep () {

  tone(BUZZER, 2400);
  delay(100);
  noTone(BUZZER);
}

void error_beep () {

  tone(BUZZER, 400);
  delay(100);
  tone(BUZZER, 400);
  delay(100);
  tone(BUZZER, 400);
  delay(100);
  noTone(BUZZER);
}

void admin_mode_start_beep () {

  tone(BUZZER, 1000);
  delay(100);
  tone(BUZZER, 2000);
  delay(100);
  tone(BUZZER, 3000);
  delay(100);
  tone(BUZZER, 4000);
  delay(100);
  noTone(BUZZER);
}

void admin_mode_end_beep () {

  tone(BUZZER, 4000);
  delay(100);
  tone(BUZZER, 3000);
  delay(100);
  tone(BUZZER, 2000);
  delay(100);
  tone(BUZZER, 1000);
  delay(100);
  noTone(BUZZER);
}

void switch_lock () {
  locked = !locked;

  if (locked) {
    digitalWrite(A2, 1);
    digitalWrite(13, 1);
  } else {
    digitalWrite(A3, 1);
    digitalWrite(13, 0);
  }

  delay(300);
  digitalWrite(A2, 0);
  digitalWrite(A3, 0);

  EEPROM.write(IS_LOCKED_ADDR, locked);
  Serial.println("Lock switched");
}

void switch_state (byte newState) {
  switch (lock_state) {

    case STATE_INIT:
      switch (newState) {
        case STATE_ADMIN:
          admin_mode_start_beep();
          break;
      }
      break;

    case STATE_LOCK:
      switch (newState) {
        case STATE_ADMIN:
          admin_mode_start_beep();
          Serial.println("Admin mode activated");
          break;
      }
      break;

    case STATE_ADMIN:
      switch (newState) {
        case STATE_ADMIN:
          break;
        default:
          admin_mode_end_beep();
          Serial.println("Admin mode deactivated");
      }
      break;
  }
  lock_state = newState;
}

boolean add_key (KeyItem key) {

  if (num_keys + 1 < sizeof(keys))
  {
    switch (key.type)
    {
      case KEY_TYPE_ANDROID:
        keys[num_keys] = key;
        num_keys++;
        write_keys_db();
        return true;
        break;

      default:
        uint8_t sector = write_nfc_tag(key.uid, key.key_A, key.key_B);
        if (sector > 0)
        {
          key.sector = sector;
          keys[num_keys] = key;
          num_keys++;
          write_keys_db();
          return true;
        }
        else
        {
          return false;
        }
    }
  }
  else
  {
    //    Serial.println("Key store is full");
    return false;
  }
}

boolean remove_key (KeyItem key) {
  KeyItem old_keys[5];
  for (byte i = 0; i < num_keys; i++) {
    old_keys[i] = keys[i];
  }

  byte next_i = 0;
  for (byte i = 0; i < num_keys; i++) {
    if (old_keys[i].uid != key.uid)
    {
      keys[next_i] = old_keys[i];
      next_i++;
    }
  }
  num_keys--;
  write_keys_db();
}

boolean add_admin_key (byte* uid) {

  KeyItem admin_key = {
    .type = KEY_TYPE_ADMIN,
    .uid = {},
    .key_A = {},
    .key_B = {},
    .sector = 0
  };
  for (byte i = 0; i < UID_SIZE; i++) {
    admin_key.uid[i] = uid[i];
  }
  for (byte i = 0; i < 6; i++) {
    admin_key.key_A[i] = random(255);
    admin_key.key_B[i] = random(255);
  }


  return add_key(admin_key);
}

boolean add_card_key (byte* uid) {

  KeyItem lock_key = {
    .type = KEY_TYPE_MIFARE_CLASSIC,
    .uid = {},
    .key_A = {},
    .key_B = {},
    .sector = 0
  };
  for (byte i = 0; i < UID_SIZE; i++) {
    lock_key.uid[i] = uid[i];
  }
  for (byte i = 0; i < 6; i++) {
    lock_key.key_A[i] = random(255);
    lock_key.key_B[i] = random(255);
  }


  return add_key(lock_key);
}

void read_keys_db () {

  KeyItem key; //Variable to store custom object read from EEPROM.

  byte db_pointer = KEYS_DB_ADDR;
  num_keys = EEPROM.read(db_pointer);

  if (num_keys > sizeof(keys)) {
    num_keys = 0;
  }

  db_pointer++;
  Serial.print("Car know ");
  Serial.print(num_keys);
  Serial.println(" keys");

  for (byte i = 0; i < num_keys; i++) {
    EEPROM.get( db_pointer, key );
    db_pointer += sizeof(key);

    //    Serial.println( "" );
    //    Serial.print( "key #" );
    //    Serial.println( (i + 1) );
    //    Serial.println( key.type );
    //    Serial.println( key.sector );
    //    dump_byte_array( key.uid, sizeof(key.uid) );
    //    Serial.println( "" );
    //    dump_byte_array( key.key_A, sizeof(key.key_A) );
    //    Serial.println( "" );
    //    dump_byte_array( key.key_B, sizeof(key.key_B) );
    //    Serial.println( "" );

    keys[i] = key;
  }
}

void write_keys_db () {

  byte db_pointer = KEYS_DB_ADDR;
  EEPROM.write(db_pointer, num_keys);
  db_pointer++;

  for (byte i = 0; i < num_keys; i++) {
    EEPROM.put(db_pointer, keys[i]);
    db_pointer += sizeof(keys[i]);
  }
}
