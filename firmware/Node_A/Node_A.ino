#include <Arduino.h>
#include <esp_system.h>

// ESP32 UART Analyzer - A
// USB serial always 115200. Monitored UART2 may change baud.
// GPIO17 TX -> peer GPIO16 RX and observer tap.
// GPIO16 RX <- peer GPIO17 TX. Common GND everywhere.
HardwareSerial linkPort(2);

static const uint8_t NODE_ID = 1;
static const uint8_t PEER_ID = (NODE_ID == 1 ? 2 : 1);
static const uint8_t DATA_TYPE = (NODE_ID << 4) | 1;
static const uint8_t ACK_TYPE = (NODE_ID << 4) | 2;
static const uint8_t CONTROL_TYPE = (NODE_ID << 4) | 3;
static const uint8_t STATUS_TYPE = (NODE_ID << 4) | 4;
static const uint8_t CTRL_ACK_TYPE = (NODE_ID << 4) | 5;
static const uint16_t MAX_PAYLOAD = 256;
static const uint16_t MAX_FRAME = MAX_PAYLOAD + 10;
static const uint8_t SYNC_COUNT = 8; // 0x55: hardware autobaud training before each frame
static const uint32_t USB_BAUD = 115200;
static const uint32_t SWITCH_DELAY_MS = 4000;

struct RxParser {
  uint8_t buffer[MAX_FRAME];
  uint16_t index = 0;
  uint16_t expected = 0;
  uint32_t lastByteMs = 0;
};
RxParser parser;

uint32_t linkBaud = 115200;
uint32_t sendIntervalMs = 1000;
uint32_t lastSendMs = 0, frameBudgetMs = 0;
bool trafficRunning = false;
bool randomSize = true;
uint16_t fixedSize = 64;
uint8_t statusEvery = 5;
uint16_t dataSeq = 0, controlSeq = 0x8000;
uint32_t dataAttempts = 0, dataSent = 0, dataReceived = 0;
uint32_t dataAcksReceived = 0, crcErrors = 0;

bool switchArmed = false;
uint32_t switchAtMs = 0, targetBaud = 0;
bool controlPending = false;
uint16_t controlPendingSeq = 0;
uint32_t controlPendingBaud = 0;
uint32_t controlRequestMs = 0;

bool supportedBaud(uint32_t x) {
  return x == 9600 || x == 19200 || x == 38400 ||
         x == 57600 || x == 115200;
}

uint16_t crc16(const uint8_t *data, size_t length) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < length; ++i) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t bit = 0; bit < 8; ++bit)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

void sendFrame(uint8_t type, uint16_t seq, const uint8_t *payload,
               uint16_t length) {
  if (length > MAX_PAYLOAD) return;
  uint8_t frame[MAX_FRAME];
  frame[0] = 0xAA;
  frame[1] = NODE_ID;
  frame[2] = type;
  frame[3] = (uint8_t)seq;
  frame[4] = (uint8_t)(seq >> 8);
  frame[5] = (uint8_t)length;
  frame[6] = (uint8_t)(length >> 8);
  for (uint16_t i = 0; i < length; ++i)
    frame[7 + i] = payload ? payload[i] : 0;
  uint16_t crc = crc16(frame + 1, 6 + length);
  frame[7 + length] = (uint8_t)crc;
  frame[8 + length] = (uint8_t)(crc >> 8);
  frame[9 + length] = 0x55;

  // 0x55 is not part of the framed payload; observer ignores it while searching for 0xAA.
  for (uint8_t i = 0; i < SYNC_COUNT; ++i) linkPort.write((uint8_t)0x55);
  linkPort.write(frame, length + 10);
}

void sendData() {
  uint16_t length = randomSize ? (uint16_t)(esp_random() % MAX_PAYLOAD + 1) : fixedSize;
  uint8_t payload[MAX_PAYLOAD];
  esp_fill_random(payload, length);
  uint16_t seq = dataSeq++;
  ++dataAttempts;
  sendFrame(DATA_TYPE, seq, payload, length);
  // Reserve line time for sync, headers, STATUS and the peer's ACK.
  frameBudgetMs = ((length + 64UL) * 10000UL + linkBaud - 1) / linkBaud;
  ++dataSent;
  Serial.printf("NODE %u TX DATA seq=%u len=%u\n", NODE_ID, seq, length);
  if (statusEvery && dataAttempts % statusEvery == 0) {
    uint8_t status[8];
    uint32_t up = millis(), baud = linkBaud;
    for (uint8_t i = 0; i < 4; ++i) {
      status[i] = (uint8_t)(up >> (8 * i));
      status[i + 4] = (uint8_t)(baud >> (8 * i));
    }
    sendFrame(STATUS_TYPE, seq, status, sizeof(status));
  }
}

void sendACK(uint16_t seq, bool control) {
  sendFrame(control ? CTRL_ACK_TYPE : ACK_TYPE, seq, nullptr, 0);
}

void armBaudSwitch(uint32_t baud) {
  targetBaud = baud;
  switchArmed = true;
  switchAtMs = millis() + SWITCH_DELAY_MS;
  Serial.printf("NODE %u: switching LINK UART to %lu in %lu ms\n",
                NODE_ID, (unsigned long)baud, (unsigned long)SWITCH_DELAY_MS);
}

void processFrame(const uint8_t *f, uint16_t n) {
  if (n < 10 || f[n - 1] != 0x55) return;
  uint16_t got = (uint16_t)f[n - 3] | ((uint16_t)f[n - 2] << 8);
  if (got != crc16(f + 1, n - 4)) {
    ++crcErrors;
    Serial.printf("NODE %u RX CRC ERROR\n", NODE_ID);
    return;
  }
  if (f[1] != PEER_ID || (f[2] >> 4) != PEER_ID) return;
  uint8_t kind = f[2] & 0x0F;
  uint16_t seq = (uint16_t)f[3] | ((uint16_t)f[4] << 8);
  uint16_t len = (uint16_t)f[5] | ((uint16_t)f[6] << 8);
  if (kind == 1) {
    ++dataReceived;
    Serial.printf("NODE %u RX DATA seq=%u len=%u CRC=OK\n", NODE_ID, seq, len);
    sendACK(seq, false);
  } else if (kind == 2) {
    ++dataAcksReceived;
    Serial.printf("NODE %u RX DATA_ACK seq=%u\n", NODE_ID, seq);
  } else if (kind == 3) {  // CONTROL
    if (len >= 5 && f[7] == 0x42) { // Coordinated baud change.
      uint32_t rate = (uint32_t)f[8] | ((uint32_t)f[9] << 8) |
                      ((uint32_t)f[10] << 16) | ((uint32_t)f[11] << 24);
      if (supportedBaud(rate) && !controlPending && !switchArmed) {
        sendACK(seq, true); // ACK on old baud first.
        armBaudSwitch(rate);
      }
    } else {
      Serial.printf("NODE %u RX USER CONTROL seq=%u len=%u\n", NODE_ID, seq, len);
      sendACK(seq, true);
    }
  } else if (kind == 5) {  // CONTROL_ACK
    if (controlPending && seq == controlPendingSeq) {
      controlPending = false;
      armBaudSwitch(controlPendingBaud);
    } else {
      Serial.printf("NODE %u RX CONTROL_ACK seq=%u\n", NODE_ID, seq);
    }
  }
}

void pollLink() {
  while (linkPort.available()) {
    uint8_t b = (uint8_t)linkPort.read();
    if (parser.index && (uint32_t)(millis() - parser.lastByteMs) > 250) {
      parser.index = 0; parser.expected = 0;
    }
    parser.lastByteMs = millis();
    if (!parser.index) {
      if (b != 0xAA) continue; // Ignore repeated 0x55 sync bytes.
      parser.buffer[parser.index++] = b;
      continue;
    }
    if (parser.index >= MAX_FRAME) {
      parser.index = 0; parser.expected = 0; continue;
    }
    parser.buffer[parser.index++] = b;
    if (parser.index == 7) {
      uint16_t len = (uint16_t)parser.buffer[5] |
                     ((uint16_t)parser.buffer[6] << 8);
      if (len > MAX_PAYLOAD) {parser.index = 0; parser.expected = 0; continue;}
      parser.expected = len + 10;
    }
    if (parser.expected && parser.index == parser.expected) {
      processFrame(parser.buffer, parser.index);
      parser.index = 0; parser.expected = 0;
    }
  }
}

void sendBaudRequest(uint32_t requested) {
  if (!supportedBaud(requested)) {
    Serial.println("Supported: 9600 19200 38400 57600 115200"); return;
  }
  if (requested == linkBaud) {
    Serial.println("Link already at requested baud"); return;
  }
  if (switchArmed || controlPending) {
    Serial.println("Another baud change is pending"); return;
  }
  uint8_t cmd[5] = {0x42, (uint8_t)requested, (uint8_t)(requested >> 8),
                    (uint8_t)(requested >> 16), (uint8_t)(requested >> 24)};
  controlPendingSeq = controlSeq++;
  controlPendingBaud = requested;
  controlPending = true;
  controlRequestMs = millis();
  sendFrame(CONTROL_TYPE, controlPendingSeq, cmd, sizeof(cmd));
  Serial.printf("NODE %u sent BAUD request %lu to peer; waiting for CONTROL_ACK\n",
                NODE_ID, (unsigned long)requested);
}

void checkSwitch() {
  if (!switchArmed || (int32_t)(millis() - switchAtMs) < 0) return;
  linkPort.flush();
  linkPort.updateBaudRate(targetBaud);
  linkBaud = targetBaud;
  parser.index = 0; parser.expected = 0;
  switchArmed = false;
  controlPending = false;
  lastSendMs = millis();
  Serial.printf("NODE %u LINK BAUD NOW %lu (USB monitor remains 115200)\n",
                NODE_ID, (unsigned long)linkBaud);
}

bool numberInRange(const char *digits, unsigned low, unsigned high, unsigned &value) {
  if (!*digits) return false;
  value = 0;
  while (*digits) {
    if (*digits < '0' || *digits > '9') return false;
    value = value * 10 + (*digits++ - '0');
    if (value > high) return false;
  }
  return value >= low;
}

void dispatchCommand(const char *input) {
  String cmd(input);
  cmd.trim();
  cmd.toUpperCase();
  unsigned value;
  if (cmd.startsWith("BAUD=")) { Serial.println("Baud control is available in V4"); return; }
  if (cmd.startsWith("BAUD=") && numberInRange(cmd.c_str()+5, 9600, 115200, value)) {
    sendBaudRequest(value);
    return;
  } else if (cmd.startsWith("INTERVAL=") && numberInRange(cmd.c_str()+9, 50, 60000, value)) {
    sendIntervalMs = value;
  } else if (cmd == "MODE=RANDOM" || cmd == "MODE=FIXED") {
    randomSize = cmd == "MODE=RANDOM";
  } else if (cmd.startsWith("SIZE=") && numberInRange(cmd.c_str()+5, 1, 256, value)) {
    fixedSize = value;
    randomSize = false;
  } else if (cmd.startsWith("STATUS=") && numberInRange(cmd.c_str()+7, 0, 100, value)) {
    statusEvery = value;
  } else if (cmd == "CONTROL") {
    uint8_t userControl[] = {0x01, (uint8_t)NODE_ID};
    uint16_t seq = controlSeq++;
    sendFrame(CONTROL_TYPE, seq, userControl, sizeof(userControl));
    Serial.printf("NODE %u TX USER CONTROL seq=%u\n", NODE_ID, seq);
  } else if (cmd == "START") {
    trafficRunning = true;
  } else if (cmd == "STOP") {
    trafficRunning = false;
  } else if (cmd == "STATS") {
    Serial.printf("NODE %u baud=%lu attempts=%lu tx=%lu rx=%lu ack=%lu crc=%lu\n",
                  NODE_ID, (unsigned long)linkBaud, (unsigned long)dataAttempts,
                  (unsigned long)dataSent, (unsigned long)dataReceived,
                  (unsigned long)dataAcksReceived, (unsigned long)crcErrors);
  } else if (cmd == "HELP") {
    Serial.println("BAUD=9600/19200/38400/57600/115200 | INTERVAL=500 | MODE=RANDOM/FIXED | SIZE=64 | STATUS=5 | CONTROL | START STOP STATS");
  } else {
    Serial.println("ERROR invalid command or value. Type HELP");
    return;
  }
  Serial.printf("OK %s\n", cmd.c_str());
}

void handleCommands() {
  static char line[64];
  static size_t used = 0;
  static bool overflow = false;
  for (unsigned budget = 64; budget && Serial.available(); --budget) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      line[used] = 0;
      if (overflow) Serial.println("ERROR command too long");
      else if (used) dispatchCommand(line);
      used = 0;
      overflow = false;
    } else if (used < sizeof(line)-1) line[used++] = c;
    else overflow = true;
  }
}

void setup() {
  Serial.begin(USB_BAUD);
  linkPort.setTxBufferSize(1024);
  linkPort.setRxBufferSize(2048);
  linkPort.begin(linkBaud, SERIAL_8N1, 16, 17);
  delay(350);
  Serial.printf("NODE %u READY: UART2 GPIO17 TX GPIO16 RX link=%lu; random DATA 1..256; ACK LEN=0\n",
                NODE_ID, (unsigned long)linkBaud);
  Serial.println("Type HELP for commands. BAUD=38400 on either node coordinates both nodes.");
}

void loop() {
  pollLink();
  handleCommands();
  checkSwitch();
  if (controlPending && !switchArmed &&
      (uint32_t)(millis() - controlRequestMs) > 6000UL) {
    controlPending = false;
    Serial.println("BAUD control ACK not seen; change cancelled locally. Check peer state.");
  }
  // Avoid new DATA close to the baud switch; finish existing frames at old baud.
  bool imminentSwitch = switchArmed && (int32_t)(switchAtMs - millis()) < 400;
  if (trafficRunning && !imminentSwitch &&
      (uint32_t)(millis() - lastSendMs) >= sendIntervalMs &&
      (uint32_t)(millis() - lastSendMs) >= frameBudgetMs) {
    lastSendMs = millis();
    sendData();
  }
}
