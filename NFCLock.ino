//#define HARD_ERASE_ARDUINO
#define DEBUG
#define AUTO_RESET_ENABLE

// RFID

#include <Wire.h>
#include <PN532.h>
#include <PN532_I2C.h>

// If using the breakout or shield with I2C, define just the pins connected
// to the IRQ and reset lines.  Use the values below (2, 3) for the shield!
#define PN532_IRQ   (2)
#define PN532_RESET (3)  // Not connected by default on the NFC Shield

PN532_I2C pn532i2c(Wire);
PN532 nfc(pn532i2c);

// BUZZER

const int BUZZER = 4;

// CRYPTO

#include <AES.h>
AES128 aes128;

// PROTOCOL

// Custom protocol
// | type | host | data |
// type:
//      - response status (ok/error)
//      - command
// host:
//      - host that sent data
// data:
//      - none for ok
//      - info for error
//      - action or data for commands

// host
const byte NFC_LAUNCH_KEY = 0x03;

// type
const byte RFID_CHECK_AID_COMMAND = 0x00;
const byte RFID_AUTH_COMMAND = 0x01;
const byte RFID_LOCK_SWITCHED = 0x02;
const byte RFID_ADD_KEY_COMMAND = 0x03;
const byte RFID_ADDING_KEY_CONFIRMED = 0x04;

const byte CARD_ERROR_RESPONSE = 0x00;
const byte CARD_OK_RESPONSE = 0x01;
const byte CARD_UID = 0x02;
const byte CARD_AUTH_RESPONSE = 0x03;

// data
// the response sent from the phone if it does not understand an APDU
const byte INFO_UNKNOWN_ERROR = 0xff;
const byte INFO_UNKNOWN_COMMAND = 0xfe;
const byte INFO_UNKNOWN_AID = 0xfd;
const byte INFO_TIMEOUT = 0xfc;
const byte INFO_NO_PIN = 0xfb;
byte AID_DATA[] = {
  0x00, /* CLA */
  0xA4, /* INS */
  0x04, /* P1  */
  0x00, /* P2  */
  0x06, /* Length of AID  */
  0xF0, 0xAB, 0xCD, 0xEF, 0x00, 0x00,
  0x00 /* Length of response  */
};

// EEPROM

#include <EEPROM.h>

#define IS_LOCKED_ADDR (0)  // is locked var address
#define KEYS_DB_ADDR (1)

// KEYS

#define PRIVATE_KEY_TYPE_A (0)
#define PRIVATE_KEY_TYPE_B (1)
uint8_t PRIVATE_KEY_DEFAULT[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
byte UID_SIZE = 4;

#define KEY_TYPE_ADMIN (0)
#define KEY_TYPE_MIFARE_CLASSIC (1)
#define KEY_TYPE_ANDROID (2)
#define KEY_TYPE_NTAG (3)

struct KeyItem
{
  byte type;
  byte uid[7];
  byte key_A[16];
  byte key_B[6];
  byte sector;
};

#define max_keys (6)
KeyItem keys[max_keys];
byte num_keys = 0;

byte locked = 1;

// RESTART

void(* resetFunc) (void) = 0;

#include "GyverTimers.h"

#define RESET_PIN (5)
byte reset_count = 0;

// STATE

#define STATE_INIT (0)
#define STATE_LOCK (1)
#define STATE_ADMIN (2)

byte lock_state = STATE_INIT;

//

void setup() {
  digitalWrite(RESET_PIN, HIGH);

  Serial.begin(9600);

  randomSeed(analogRead(0));

  pinMode(RESET_PIN, OUTPUT);
  pinMode(13, OUTPUT);
  pinMode(A2, OUTPUT);
  pinMode(A3, OUTPUT);

  pinMode(BUZZER, OUTPUT);

  noTone(BUZZER);

  // NFC

  start_rfid_reader();

  locked = EEPROM.read(IS_LOCKED_ADDR);
  if (locked > 0) locked = 1;
#ifdef DEBUG
  digitalWrite(13, locked);
#endif

  //

#ifdef HARD_ERASE_ARDUINO
  reset_db();
#endif

  //

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

  //

  Timer1.setPeriod(4000000);
  Timer1.enableISR(CHANNEL_A);
}

void loop() {

  KeyItem key;
  boolean known_key_found;
  uint8_t success;
  byte responce[4];

  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };  // Buffer to store the returned UID
  uint8_t uidLength;                        // Length of the UID (4 or 7 bytes depending on ISO14443A card type)
  //  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength);
  //  if (success) {
  if (nfc.inListPassiveTarget(uid, &uidLength)) {

    if (lock_state == STATE_INIT) {

      success = create_key(uid, KEY_TYPE_ADMIN);
      if (success)
      {
        admin_mode_start_beep();
        admin_mode_end_beep();
#ifdef DEBUG
        Serial.println("Admin key added");
#endif
        switch_state(STATE_LOCK);
      }
      else
      {
        error_beep();
      }
    }
    else
    {
      known_key_found = false;

      success = read_uid_android(responce);
      if (success)
      {
        for (uint8_t i = 0; i < 4; i++)
        {
          uid[i] = responce[i];
        }
      }

      for (byte i = 0; i < num_keys; i++) {
        if (memcmp(uid, keys[i].uid, get_uid_size(key.type)) == 0) {
          key = keys[i];
          known_key_found = true;
          break;
        }
      }


      if (known_key_found)
      {
#ifdef DEBUG
        Serial.println("Known key found");
        nfc.PrintHex(uid, uidLength);
#endif
        if (key.type == KEY_TYPE_ADMIN)
        {
          success = auth_mifare(uid, key.key_A, key.sector, PRIVATE_KEY_TYPE_A);
          if (success)
          {
            switch (lock_state) {

              case STATE_LOCK:
                switch_state(STATE_ADMIN);
                break;

              case STATE_ADMIN:
                error_beep();
                switch_state(STATE_LOCK);
            }
          }
        }
        else if (key.type == KEY_TYPE_MIFARE_CLASSIC)
        {
          switch (lock_state) {

            case STATE_LOCK:
              success = auth_mifare(uid, key.key_A, key.sector, PRIVATE_KEY_TYPE_A);
              if (success)
              {
                switch_lock();
                ready_beep();
              }
              else
              {
                error_beep();
              }
              break;

            case STATE_ADMIN:
              remove_key(key);
              ready_beep ();
              ready_beep ();
              ready_beep ();
              ready_beep ();
              break;
          }
          switch_state(STATE_LOCK);
        }
        else if (key.type == KEY_TYPE_NTAG)
        {
          switch (lock_state) {

            case STATE_LOCK:
              success = auth_ntag(key.key_A, key.key_B);
              if (success)
              {
                switch_lock();
                ready_beep();
              }
              else
              {
                error_beep();
              }
              break;

            case STATE_ADMIN:
              remove_key(key);
              ready_beep ();
              ready_beep ();
              ready_beep ();
              ready_beep ();
              break;
          }
          switch_state(STATE_LOCK);
        }
        else if (key.type == KEY_TYPE_ANDROID)
        {
          // it is android key (KEY_TYPE_ANDROID)
          switch (lock_state) {

            case STATE_LOCK:
              success = auth_android(key.key_A);
              if (success)
              {
                switch_lock();
                ready_beep();
              }
              else
              {
                error_beep();
              }
              break;

            case STATE_ADMIN:
              remove_key(key);
              ready_beep ();
              ready_beep ();
              ready_beep ();
              ready_beep ();
              break;
          }
          switch_state(STATE_LOCK);
        }
        else
        {
#ifdef DEBUG
          Serial.println("Unknown key type found");
#endif
          error_beep();
          switch_state(STATE_LOCK);
        }
      }
      else
      {
#ifdef DEBUG
        Serial.println("Unknown key found");
        nfc.PrintHex( uid, uidLength );
#endif
        switch (lock_state) {

          case STATE_ADMIN:
            if (uidLength == 4) {
              success = create_key(uid, KEY_TYPE_ANDROID);
              if (success)
              {
#ifdef DEBUG
                Serial.println("New android device added");
#endif
                ready_beep ();
                ready_beep ();
              }
              else
              {
                success = create_key(uid, KEY_TYPE_MIFARE_CLASSIC);
                if (success)
                {
#ifdef DEBUG
                  Serial.println("New card added");
#endif
                  ready_beep ();
                  ready_beep ();
                }
                else
                {
                  error_beep();
                }
              }
            } else if (uidLength == 7) {
              success = create_key(uid, KEY_TYPE_NTAG);
              if (success)
              {
#ifdef DEBUG
                Serial.println("New ntag added");
#endif
                ready_beep ();
                ready_beep ();
              }
              else
              {
                error_beep();
              }
            }
            switch_state(STATE_LOCK);
            break;

          default:
            error_beep();
        }
      }
    }
  } else {
    if (lock_state != STATE_INIT) {
      switch_state(STATE_LOCK);

      //      resetFunc();
    }
  }
  delay(1000);
}

boolean check_if_key_exist(KeyItem key) {

  for (byte i = 0; i < num_keys; i++) {
    if (memcmp(key.uid, keys[i].uid, get_uid_size(key.type)) == 0)
    {
      return true;
    }
  }

  return false;
}

uint8_t get_uid_size(byte key_type) {

  if (key_type == KEY_TYPE_NTAG) {
    return 7;
  }

  return 4;
}

void send_command(byte command, byte* data, uint8_t dataLength, byte *response) {
  byte sendingData[32];
  if (command == RFID_CHECK_AID_COMMAND) {
    for (byte j = 0; j < dataLength; j++) {
      sendingData[j] = data[j];
    }
  } else {
    sendingData[0] = command;
    sendingData[1] = NFC_LAUNCH_KEY;
    for (byte j = 0; j < dataLength; j++) {
      sendingData[2 + j] = data[j];
    }
    if (dataLength <= 0) {
      // we cannot send 1 byte, so just add some salt at the end
      sendingData[2] = 0xff;
      dataLength = 1;
    }
    dataLength = dataLength + 2;
  }

  uint8_t responseLength = 32;

  if (nfc.inDataExchange(sendingData, dataLength, response, &responseLength)) {
    if (responseLength > 0) {
      return;
    }
  }

  // unknown error
  response[0] = CARD_ERROR_RESPONSE;
  response[1] = INFO_TIMEOUT;
}

boolean auth_mifare(byte* uid, byte* key, uint8_t sector, uint8_t key_type) {
  uint8_t success;

  success = nfc.mifareclassic_AuthenticateBlock(uid, UID_SIZE, sector * 4, key_type, key);

  if (!success)
  {
#ifdef DEBUG
    Serial.println("auth_mifare: Auth failed");
#endif
  }

  return success;
}

boolean auth_ntag(byte* keyA, byte* keyB) {
  uint8_t success;
  success = nfc.ntag21x_auth(keyA, keyB);

  if (!success)
  {
#ifdef DEBUG
    Serial.println("auth_ntag: Auth failed");
#endif
  }

  return success;
}


boolean read_uid_android(byte *response) {
  byte responseData[32];

  send_command(RFID_CHECK_AID_COMMAND, AID_DATA, sizeof(AID_DATA), responseData);

  byte type = responseData[0];
  byte single_data;
  switch (type) {

    case CARD_UID:
      for (byte j = 0; j < 4; j++) {
        response[j] = responseData[j + 1];
      }
      return true;

    case CARD_ERROR_RESPONSE:
      single_data = responseData[1];
      switch (single_data) {
        case INFO_NO_PIN:
          break;
        case INFO_TIMEOUT:
          break;
      }
#ifdef DEBUG
      Serial.println("CARD_ERROR_RESPONSE");
#endif
      break;
  }

  return false;
}


boolean auth_android(byte* keya) {
  byte responseData[32];

  byte rfid_data[16];
  uint8_t success = false;

  for (byte i = 0; i < 16; i++) {
    rfid_data[i] = random(255);
  }

  send_command(RFID_AUTH_COMMAND, rfid_data, sizeof(rfid_data), responseData);

  byte encrypted_str[16];
  byte buffer[16];
  for (byte j = 0; j < 16; j++) {
    encrypted_str[j] = responseData[j + 1];
  }

  aes128.setKey(keya, aes128.keySize());
  aes128.decryptBlock(buffer, encrypted_str);
  if (memcmp(buffer, rfid_data, 16) == 0) {
    success = true;
  }

  if (!success)
  {
#ifdef DEBUG
    Serial.println("auth_android: Auth failed");
#endif
  }

  return success;
}


////////////
// BEEPS
////////////

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


/////////////////
// LOCK MANAGEMENT
/////////////////

void switch_lock () {
  locked = !locked;

  if (locked) {
    digitalWrite(A2, 1);

#ifdef DEBUG
    digitalWrite(13, 1);
#endif
  } else {
    digitalWrite(A3, 1);
#ifdef DEBUG
    digitalWrite(13, 0);
#endif
  }

  delay(300);
  digitalWrite(A2, 0);
  digitalWrite(A3, 0);

  EEPROM.write(IS_LOCKED_ADDR, locked);

  byte responseData[4];
  byte data[1];
  data[0] = locked;

  send_command(RFID_LOCK_SWITCHED, data, sizeof(data), responseData);

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
#ifdef DEBUG
          Serial.println("Admin mode activated");
#endif
          break;
      }
      break;

    case STATE_ADMIN:
      switch (newState) {
        case STATE_ADMIN:
          break;
        default:
          admin_mode_end_beep();
#ifdef DEBUG
          Serial.println("Admin mode deactivated");
#endif
      }
      break;
  }
  lock_state = newState;
}

////////////////
// KEYS MANAGEMENT
////////////////

boolean create_key (byte* uid, byte key_type) {

  KeyItem lock_key = {
    .type = key_type,
    .uid = {},
    .key_A = {},
    .key_B = {},
    .sector = 0
  };
  for (byte i = 0; i < get_uid_size(key_type); i++) {
    lock_key.uid[i] = uid[i];
  }
  for (byte i = 0; i < 6; i++) {
    lock_key.key_A[i] = random(255);
    lock_key.key_B[i] = random(255);
  }

  return add_key(lock_key);
}

boolean add_key (KeyItem key) {

  boolean success = false;
  if (num_keys + 1 <= max_keys) {
    switch (key.type)
    {
      case KEY_TYPE_ANDROID:
        success = write_key_to_android(key);
        break;

      case KEY_TYPE_NTAG:
        success = write_key_to_ntag(key);
        break;

      case KEY_TYPE_ADMIN:
      case KEY_TYPE_MIFARE_CLASSIC:
      default:
        uint8_t sector = write_key_to_mifare(key);
        if (sector > 0) {
          success = true;
          key.sector = sector;
#ifdef DEBUG
          Serial.print("WRITING KEY: this key was written ");
          nfc.PrintHex( key.uid, sizeof(key.uid) );
          Serial.print(" to sector ");
          Serial.println(sector);
#endif
        }
    }
  } else {
#ifdef DEBUG
    Serial.println("Key store is full");
#endif
  }

  if (success) {
    keys[num_keys] = key;
    num_keys++;
    write_keys_to_db();
    return true;
  }

  return false;
}

boolean remove_key (KeyItem key) {
  byte replace_i = 0;
  for (byte i = 0; i < num_keys; i++) {
    if (memcmp(key.uid, keys[i].uid, UID_SIZE) == 0) {
      replace_i = i;
      break;
    }
  }
  // Admin key (i == 0) cannot be removed
  if (replace_i > 0) {
    for (byte i = replace_i; i < num_keys - 1; i++) {
      keys[i] = keys[i + 1];
    }
    num_keys--;
    write_keys_to_db();

    if (key.type == KEY_TYPE_MIFARE_CLASSIC) {
      remove_key_from_mifare(key);
    } else if (key.type == KEY_TYPE_NTAG) {
      remove_key_from_ntag(key);
    }
#ifdef DEBUG
    Serial.println("ERASING KEY: this key was removed:");
    nfc.PrintHex( key.uid, sizeof(key.uid) );
#endif
  }
}

uint8_t write_key_to_mifare(KeyItem key) {
  uint8_t success = false;
  // 0 is not valid sector
  uint8_t sector = 0;
  uint8_t uidLength;

  for (uint8_t i = 1; i < 15; i++) {
    success = auth_mifare(key.uid, PRIVATE_KEY_DEFAULT, i, PRIVATE_KEY_TYPE_A);
    if (success) {
      if (!check_if_key_exist(key)) {
        sector = i;
      }
      break;
    } else {
      nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, key.uid, &uidLength, 1000);
    }
  }

  if (success) {
    uint8_t access_bits[4] = { 0x78, 0x77, 0x88, 0xFF };
    uint8_t newkeys[16];
    for (uint8_t i = 0; i < 6; i++) {
      newkeys[i] = key.key_A[i];
    }
    for (uint8_t i = 0; i < 4; i++) {
      newkeys[6 + i] = access_bits[i];
    }
    for (uint8_t i = 0; i < 6; i++) {
      newkeys[10 + i] = key.key_B[i];
    }
    success = nfc.mifareclassic_WriteDataBlock(sector * 4 + 3, newkeys);
  }

  return sector;
}

uint8_t write_key_to_ntag(KeyItem key) {
  uint8_t success = false;
  uint8_t data[4];
  // try to auth
  //  data[0] = 0x00;
  //  data[1] = 0x01;
  //  data[2] = 0x02;
  //  data[3] = 0x03;
  //  success = nfc.ntag21x_auth(data);

  nfc.mifareultralight_ReadPage(3, data);
  int capacity = data[2] * 8;

  uint8_t cfg_page_base = 0x29;   // NTAG213
  if (capacity == 0x3E) {
    cfg_page_base = 0x83;       // NTAG215
  } else if (capacity == 0x6D) {
    cfg_page_base = 0xE3;       // NTAG216
  }

  // Update PACK
//  data[0] = 0x07;
//  data[1] = 0x77;
//  data[2] = 0x00;
//  data[3] = 0x00;
  success = nfc.mifareultralight_WritePage(cfg_page_base + 3, key.key_B);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // disable r/w
  // | PROT | CFG_LCK | RFUI | NFC_CNT_EN | NFC_CNT_PWD_PROT | AUTHLIM (2:0) |
  data[0] = (1 << 7) | 0x0;
  success = nfc.mifareultralight_WritePage(cfg_page_base + 1, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // Update password
  success = nfc.mifareultralight_WritePage(cfg_page_base + 2, key.key_A);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // Update AUTH0 byte
  success = nfc.mifareultralight_ReadPage(cfg_page_base, data);
  data[3] = cfg_page_base; // restrict data from cfg_page_base
  success = nfc.mifareultralight_WritePage(cfg_page_base, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  return 1;
}

uint8_t remove_key_from_mifare(KeyItem key) {
  uint8_t success = false;

  success = auth_mifare(key.uid, key.key_B, key.sector, PRIVATE_KEY_TYPE_B);

  if (success) {
    // transpot configuration
    uint8_t access_bits[4] = { 0xFF, 0x07, 0x80, 0xFF };
    uint8_t newkeys[16];
    for (uint8_t i = 0; i < 6; i++) {
      newkeys[i] = PRIVATE_KEY_DEFAULT[i];
    }
    for (uint8_t i = 0; i < 4; i++) {
      newkeys[6 + i] = access_bits[i];
    }
    for (uint8_t i = 0; i < 6; i++) {
      newkeys[10 + i] = PRIVATE_KEY_DEFAULT[i];
    }
    success = nfc.mifareclassic_WriteDataBlock(key.sector * 4 + 3, newkeys);

    if (!success) {
#ifdef DEBUG
      Serial.println("ERASING KEY: cannot write default key with key B");
#endif
    }
  }
  else {
#ifdef DEBUG
    Serial.println("ERASING KEY: cannot authentificate with key B");
#endif
  }

  return success;
}

uint8_t remove_key_from_ntag(KeyItem key) {
  uint8_t success = false;
  uint8_t data[4];
  // try to auth
  success = auth_ntag(key.key_A, key.key_B);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  nfc.mifareultralight_ReadPage(3, data);
  int capacity = data[2] * 8;

  uint8_t cfg_page_base = 0x29;   // NTAG213
  if (capacity == 0x3E) {
    cfg_page_base = 0x83;       // NTAG215
  } else if (capacity == 0x6D) {
    cfg_page_base = 0xE3;       // NTAG216
  }

  // disable r/w
  // | PROT | CFG_LCK | RFUI | NFC_CNT_EN | NFC_CNT_PWD_PROT | AUTHLIM (2:0) |
  data[0] = (0 << 7) | 0x0;
  success = nfc.mifareultralight_WritePage(cfg_page_base + 1, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // Update PACK
  data[0] = 0x00;
  data[1] = 0x00;
  data[2] = 0x00;
  data[3] = 0x00;
  success = nfc.mifareultralight_WritePage(cfg_page_base + 3, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // Update password
  success = nfc.mifareultralight_WritePage(cfg_page_base + 2, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  // Update AUTH0 byte
  success = nfc.mifareultralight_ReadPage(cfg_page_base, data);
  data[3] = 0xFF; // restrict data from cfg_page_base
  success = nfc.mifareultralight_WritePage(cfg_page_base, data);
  if (!success)
  {
    Serial.println(" ERROR!");
    return 0;
  }

  return 1;
}

boolean write_key_to_android(KeyItem key) {
  byte responseData[32];

  send_command(RFID_ADD_KEY_COMMAND, key.key_A, sizeof(key.key_A), responseData);

  byte type = responseData[0];
  byte single_data;
  switch (type) {
    case CARD_OK_RESPONSE:
      byte buffer[16];
      for (byte j = 0; j < 16; j++) {
        buffer[j] = responseData[j + 1];
      }
      if (memcmp(buffer, key.key_A, 16) == 0) {
        return true;
      }
      break;

    case CARD_ERROR_RESPONSE:
      single_data = responseData[1];
      switch (single_data) {
        case INFO_NO_PIN:
          break;
        case INFO_TIMEOUT:
          break;
      }
      break;
  }
  return false;
}

void read_keys_db () {

  KeyItem key; //Variable to store custom object read from EEPROM.

  byte db_pointer = KEYS_DB_ADDR;
  num_keys = EEPROM.read(db_pointer);

  if (num_keys > max_keys) {
    num_keys = 0;
  }

  db_pointer++;

  for (byte i = 0; i < num_keys; i++) {
    EEPROM.get( db_pointer, key );
    db_pointer += sizeof(key);

#ifdef DEBUG
    Serial.println( "" );
    Serial.print( "key #" );
    Serial.println( (i + 1) );
    Serial.println( key.type );
    Serial.println( key.sector );
    nfc.PrintHex( key.uid, sizeof(key.uid) );
#endif

    keys[i] = key;
  }
}

void write_keys_to_db () {
  byte db_pointer = KEYS_DB_ADDR;
  EEPROM.write(db_pointer, num_keys);
  db_pointer++;

  for (byte i = 0; i < num_keys; i++) {
    EEPROM.put(db_pointer, keys[i]);
    db_pointer += sizeof(keys[i]);
  }
}

void reset_db () {
  byte db_pointer = KEYS_DB_ADDR;
  EEPROM.write(db_pointer, 0);
  write_keys_to_db();
}


////////////////
// SELF CARE
////////////////

void start_rfid_reader () {
  nfc.begin();
  boolean success = check_rfid_reader();
  if (success) {
    // configure board to read RFID tags
    nfc.SAMConfig();
  }
}

boolean check_rfid_reader () {
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (! versiondata) {
#ifdef DEBUG
    Serial.print("Didn't find PN53x board");
    error_beep();
#endif
    return false;
  }
#ifdef DEBUG
  // Got ok data, print it out!
  Serial.print("Found chip PN5"); Serial.println((versiondata >> 24) & 0xFF, HEX);
  Serial.print("Firmware ver. "); Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.'); Serial.println((versiondata >> 8) & 0xFF, DEC);
  ready_beep();
#endif
  return true;
}

ISR(TIMER1_A) {  // пишем  в сериал
  reset_count++;
  if (reset_count > 10) {
    reset_count = 0;
#ifdef AUTO_RESET_ENABLE
    digitalWrite(RESET_PIN, LOW);
#endif
  }
}
