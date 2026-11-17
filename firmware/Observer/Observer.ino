#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/task.h>

// Passive ESP32-WROOM-32 observer.
// Line 1: Node A GPIO17 TX -> Observer GPIO16 UART2 RX (GPIO17 TX NOT connected)
// Line 2: Node B GPIO17 TX -> Observer GPIO27 UART1 RX (no observer TX)
// ALL THREE BOARDS share GND. Observer USB JSON = 921600 baud.
// Requires Arduino-ESP32 core 3.x for HardwareSerial.begin(0,...) autobaud API.
// Autobaud is performed by ESP32 UART hardware, not by assuming 115200.
HardwareSerial tapA(2), tapB(1);

static const int RX_PINS[2] = {16, 27};
static const uint32_t PC_BAUD = 921600;
static const uint16_t MAX_PAYLOAD = 256;
static const uint16_t MAX_FRAME = MAX_PAYLOAD + 10;
static const uint8_t SYNC_COUNT = 8;
static const uint32_t ACK_TIMEOUT_US = 2000000UL;
static const uint32_t AUTOBAUD_TIMEOUT_MS = 2600UL;
static const uint32_t LOST_AFTER_MS = 5500UL;
static const uint32_t RETRY_AFTER_MS = 2200UL;
static const uint16_t PENDING_SLOTS = 128;

static const uint32_t SUPPORTED_BAUD[] = {9600, 19200, 38400, 57600, 115200};

struct ParseState {
  uint8_t data[MAX_FRAME];
  uint16_t index = 0, total = 0;
  uint32_t lastByteMs = 0;
};
struct LineState {
  bool locked = false;
  uint32_t baud = 0, measured = 0;
  uint32_t lastAttemptMs = 0, lastValidMs = 0;
  uint8_t source = 0;
  uint32_t frames = 0, data = 0, acks = 0, status = 0, controls = 0;
  uint32_t frameBytes = 0, payloadBytes = 0, wireBytes = 0;
  uint32_t crcErrors = 0, frameErrors = 0, seqGaps = 0, duplicates = 0, outOfOrder = 0;
  bool haveSequence = false;
  uint16_t lastSequence = 0;
  uint32_t previousFrames = 0, previousPayloadBytes = 0, previousWireBytes = 0;
};
struct Pending {
  bool active = false;
  uint16_t seq = 0;
  uint32_t whenUs = 0;
};
struct AckMetrics {
  uint32_t matched = 0, timeouts = 0, unmatchedAcks = 0, capacityMisses = 0;
  uint32_t lastUs = 0, minUs = 0xFFFFFFFFUL, maxUs = 0;
  double sumUs = 0, jitterSumUs = 0;
  uint32_t lastForJitter = 0;
};

void updateSequence(LineState &s, uint16_t seq);

ParseState parsers[2];
LineState lines[2];
Pending pending[2][PENDING_SLOTS];
AckMetrics ackForSource[2];
uint32_t lastReportMs = 0, lastTimeoutCheckMs = 0;

uint16_t crc16(const uint8_t *data, size_t n) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < n; ++i) {
    crc ^= (uint16_t)data[i] << 8;
    for (uint8_t b = 0; b < 8; ++b)
      crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

uint32_t nearestSupported(uint32_t measured) {
  if (measured == 0) return 0;
  uint32_t best = 0, diffBest = 0xFFFFFFFFUL;
  for (uint8_t i = 0; i < sizeof(SUPPORTED_BAUD) / sizeof(SUPPORTED_BAUD[0]); ++i) {
    uint32_t candidate = SUPPORTED_BAUD[i];
    uint32_t diff = measured > candidate ? measured - candidate : candidate - measured;
    if (diff < diffBest) {diffBest = diff; best = candidate;}
  }
  // Reject an inaccurate/noisy autobaud result rather than inventing an estimate.
  return diffBest <= best / 20 ? best : 0;
}

const char *typeName(uint8_t t) {
  switch (t & 0x0F) {
    case 1: return "DATA";
    case 2: return "ACK";
    case 3: return "CONTROL";
    case 4: return "STATUS";
    case 5: return "CTRL_ACK";
    default: return "UNKNOWN";
  }
}

void emitHex(const uint8_t *f, size_t n) {
  const char hex[] = "0123456789ABCDEF";
  char encoded[2 * MAX_FRAME];
  for (size_t i = 0; i < n; ++i) {
    encoded[2*i] = hex[f[i] >> 4];
    encoded[2*i+1] = hex[f[i] & 15];
  }
  Serial.write((const uint8_t*)encoded, 2*n);
}

void emitError(uint8_t line, const char *reason, const uint8_t *f, uint16_t n) {
  Serial.printf("{\"event\":\"error\",\"line\":%u,\"error\":\"%s\",\"raw_hex\":\"",
                line + 1, reason);
  emitHex(f, n);
  Serial.println("\"}");
}

void noteTimeout(uint8_t sourceIndex) {
  ackForSource[sourceIndex].timeouts++;
  Serial.printf("{\"event\":\"ack_timeout\",\"source\":%u}\n", sourceIndex + 1);
}

void recordData(uint8_t sourceIndex, uint16_t seq, uint32_t stamp) {
  Pending *freeSlot = nullptr;
  for (Pending &entry : pending[sourceIndex]) {
    if (entry.active && entry.seq == seq) return;
    if (!entry.active && !freeSlot) freeSlot = &entry;
  }
  if (!freeSlot) {
    ++ackForSource[sourceIndex].capacityMisses;
    Serial.printf("{\"event\":\"ack_capacity\",\"source\":%u,\"seq\":%u}\n", sourceIndex+1, seq);
    return;
  }
  freeSlot->seq = seq;
  freeSlot->whenUs = stamp;
  freeSlot->active = true;
}

void matchACK(uint8_t ackSource, uint16_t seq, uint32_t stamp) {
  uint8_t originalIndex = ackSource == 1 ? 1 : 0;
  Pending *found = nullptr;
  for (Pending &entry : pending[originalIndex]) {
    if (entry.active && entry.seq == seq) { found = &entry; break; }
  }
  if (!found) {
    ++ackForSource[originalIndex].unmatchedAcks;
    return;
  }
  Pending &p = *found;
  uint32_t elapsed = stamp - p.whenUs;
  p.active = false;
  if (elapsed > ACK_TIMEOUT_US) {
    noteTimeout(originalIndex);
    return;
  }
  AckMetrics &a = ackForSource[originalIndex];
  if (a.matched > 0) {
    a.jitterSumUs += elapsed > a.lastForJitter ?
                     elapsed - a.lastForJitter : a.lastForJitter - elapsed;
  }
  a.lastForJitter = elapsed;
  a.lastUs = elapsed;
  if (elapsed < a.minUs) a.minUs = elapsed;
  if (elapsed > a.maxUs) a.maxUs = elapsed;
  a.sumUs += elapsed;
  a.matched++;
  Serial.printf("{\"event\":\"latency\",\"source\":%u,\"seq\":%u,\"latency_us\":%lu}\n",
                originalIndex + 1, seq, (unsigned long)elapsed);
}

void updateSequence(LineState &s, uint16_t seq) {
  if (!s.haveSequence) {s.haveSequence = true; s.lastSequence = seq; return;}
  uint16_t delta = (uint16_t)(seq - s.lastSequence);
  if (delta == 0) ++s.duplicates;
  else if (delta < 32768) {
    if (delta > 1) s.seqGaps += delta - 1;
    s.lastSequence = seq;
  } else ++s.outOfOrder;
}

void finishFrame(uint8_t line, const uint8_t *f, uint16_t n) {
  LineState &s = lines[line];
  if (f[n - 1] != 0x55) {
    s.frameErrors++;
    emitError(line, "END_MARKER", f, n);
    return;
  }
  uint16_t seen = (uint16_t)f[n - 3] | ((uint16_t)f[n - 2] << 8);
  if (seen != crc16(f + 1, n - 4)) {
    s.crcErrors++;
    emitError(line, "CRC", f, n);
    return;
  }
  uint8_t source = f[1];
  uint8_t kind = f[2] & 0x0F;
  if ((source != 1 && source != 2) || (f[2] >> 4) != source || kind < 1 || kind > 5) {
    s.frameErrors++;
    emitError(line, "HEADER", f, n);
    return;
  }
  uint16_t seq = (uint16_t)f[3] | ((uint16_t)f[4] << 8);
  uint16_t payloadLength = (uint16_t)f[5] | ((uint16_t)f[6] << 8);
  uint32_t nowUs = micros();
  s.lastValidMs = millis();
  if (source != s.source) {
    s.source = source;
    Serial.printf("{\"event\":\"direction\",\"line\":%u,\"source\":%u,\"destination\":%u}\n",
                  line + 1, source, 3 - source);
  }
  s.frames++;
  s.frameBytes += n;
  if (kind == 1) s.payloadBytes += payloadLength;
  s.wireBytes += n + SYNC_COUNT;  // Valid frames + known sync pattern, not raw-wire capture.
  if (kind == 1) {s.data++; updateSequence(s, seq); recordData(source - 1, seq, nowUs);}
  else if (kind == 2) {s.acks++; matchACK(source, seq, nowUs);}
  else if (kind == 3 || kind == 5) s.controls++;
  else if (kind == 4) s.status++;

  Serial.printf("{\"event\":\"frame\",\"ts_us\":%lu,\"line\":%u,\"source\":%u,"
                "\"destination\":%u,\"type\":\"%s\",\"seq\":%u,\"length\":%u,"
                "\"frame_bytes\":%u,\"wire_bytes\":%u,\"crc_ok\":true,\"raw_hex\":\"",
                (unsigned long)nowUs, line + 1, source, 3 - source, typeName(f[2]),
                seq, payloadLength, n, n + SYNC_COUNT);
  emitHex(f, n);
  Serial.println("\"}");
}

void readByte(uint8_t line, uint8_t b) {
  ParseState &p = parsers[line];
  LineState &s = lines[line];
  if (p.index && (uint32_t)(millis() - p.lastByteMs) > 250) {
    ++s.frameErrors;
    emitError(line, "TIMEOUT", p.data, p.index);
    p.index = 0; p.total = 0;
  }
  p.lastByteMs = millis();
  if (p.index == 0) {
    if (b != 0xAA) return; // Ignore 0x55 synchronization bytes.
    p.data[p.index++] = b;
    return;
  }
  if (p.index >= MAX_FRAME) { ++s.frameErrors; p.index = 0; p.total = 0; return; }
  p.data[p.index++] = b;
  if (p.index == 7) {
    uint16_t length = (uint16_t)p.data[5] | ((uint16_t)p.data[6] << 8);
    if (length > MAX_PAYLOAD) {
      ++s.frameErrors;
      emitError(line, "LENGTH", p.data, p.index);
      p.index = 0; p.total = 0;
      return;
    }
    p.total = length + 10;
  }
  if (p.total && p.index == p.total) {
    finishFrame(line, p.data, p.index);
    p.index = 0; p.total = 0;
  }
}

struct Detection { uint8_t line; uint32_t measured; };
QueueHandle_t requests, results;
bool searching[2] = {false, false};

void detectionWorker(void *) {
  uint8_t line;
  for (;;) {
    if (xQueueReceive(requests, &line, portMAX_DELAY) != pdTRUE) continue;
    HardwareSerial &port = line == 0 ? tapA : tapB;
    port.end();
    port.setRxBufferSize(4096);
    port.begin(0, SERIAL_8N1, RX_PINS[line], -1, false, AUTOBAUD_TIMEOUT_MS);
    Detection result = {line, port.baudRate()};
    uint32_t chosen = nearestSupported(result.measured);
    if (chosen) port.updateBaudRate(chosen);
    else port.end();
    xQueueSend(results, &result, portMAX_DELAY);
  }
}

void requestDetection(uint8_t line) {
  if (searching[line] || xQueueSend(requests, &line, 0) != pdTRUE) return;
  searching[line] = true;
  lines[line].locked = false;
  lines[line].baud = 0;
  parsers[line] = ParseState();
  Serial.printf("{\"event\":\"baud_search\",\"line\":%u}\n", line + 1);
}

void finishDetection() {
  Detection result;
  while (xQueueReceive(results, &result, 0) == pdTRUE) {
    uint8_t i = result.line;
    searching[i] = false;
    LineState &s = lines[i];
    s.lastAttemptMs = millis();
    s.measured = result.measured;
    s.baud = nearestSupported(s.measured);
    s.locked = s.baud != 0;
    s.lastValidMs = millis();
    Serial.printf("{\"event\":\"%s\",\"line\":%u,\"baud\":%lu,\"measured\":%lu}\n",
                  s.locked ? "baud_detected" : "baud_failed", i + 1,
                  (unsigned long)s.baud, (unsigned long)s.measured);
  }
}

void checkPending() {
  uint32_t now = micros();
  for (uint8_t src = 0; src < 2; ++src)
    for (uint16_t i = 0; i < PENDING_SLOTS; ++i) {
      Pending &p = pending[src][i];
      if (p.active && (uint32_t)(now - p.whenUs) > ACK_TIMEOUT_US) {
        p.active = false;
        noteTimeout(src);
      }
    }
}

void reportStats() {
  uint32_t now = millis();
  uint32_t elapsed = now - lastReportMs;
  if (elapsed < 1000) return;
  lastReportMs = now;
  for (uint8_t i = 0; i < 2; ++i) {
    LineState &s = lines[i];
    uint32_t dFrames = s.frames - s.previousFrames;
    uint32_t dWire = s.wireBytes - s.previousWireBytes;
    uint32_t dPayload = s.payloadBytes - s.previousPayloadBytes;
    s.previousFrames = s.frames;
    s.previousWireBytes = s.wireBytes;
    s.previousPayloadBytes = s.payloadBytes;
    float wireKbps = dWire * 8.0f / elapsed;
    float payloadKbps = dPayload * 8.0f / elapsed;
    float frameRate = dFrames * 1000.0f / elapsed;
    float utilization = s.baud ?
        (dWire * 10.0f * 100000.0f / (s.baud * (float)elapsed)) : 0;
    float efficiency = s.wireBytes ? (100.0f * s.payloadBytes / s.wireBytes) : 0;
    uint8_t originalSrc = s.source;
    AckMetrics &a = ackForSource[originalSrc ? originalSrc - 1 : i];
    float pdr = (originalSrc && s.data) ? (100.0f * a.matched / s.data) : 0;
    char pdrText[24], averageText[32], efficiencyText[24], jitterText[32];
    strcpy(pdrText, "null");
    strcpy(averageText, "null");
    strcpy(efficiencyText, "null");
    strcpy(jitterText, "null");
    if (originalSrc && s.data && !a.capacityMisses)
      snprintf(pdrText, sizeof(pdrText), "%.2f", pdr);
    if (originalSrc && a.matched)
      snprintf(averageText, sizeof(averageText), "%.2f", a.sumUs / a.matched);
    if (s.wireBytes)
      snprintf(efficiencyText, sizeof(efficiencyText), "%.2f", efficiency);
    if (originalSrc && a.matched > 1)
      snprintf(jitterText, sizeof(jitterText), "%.2f", a.jitterSumUs / (a.matched - 1));
    Serial.printf("{\"event\":\"stats\",\"line\":%u,\"source\":%u,\"baud\":%lu,"
                  "\"locked\":%s,\"frames\":%lu,\"data\":%lu,\"acks\":%lu,\"status\":%lu,"
                  "\"controls\":%lu,\"bytes\":%lu,\"wire_bytes\":%lu,\"payload_bytes\":%lu,"
                  "\"crc_errors\":%lu,\"framing_errors\":%lu,\"seq_gaps\":%lu,\"duplicates\":%lu,"
                  "\"out_of_order\":%lu,\"frame_rate_fps\":%.2f,\"throughput_kbps\":%.3f,"
                  "\"payload_kbps\":%.3f,\"utilization_pct\":%.2f,\"efficiency_pct\":%s,"
                  "\"ack_capacity\":%lu,\"matched_acks\":%lu,\"ack_timeouts\":%lu,\"pdr_pct\":%s,"
                  "\"avg_ack_rtt_us\":%s,\"min_ack_rtt_us\":%lu,\"max_ack_rtt_us\":%lu,"
                  "\"jitter_us\":%s}\n",
                  i + 1, originalSrc, (unsigned long)s.baud, s.locked ? "true" : "false",
                  (unsigned long)s.frames, (unsigned long)s.data, (unsigned long)s.acks,
                  (unsigned long)s.status, (unsigned long)s.controls,
                  (unsigned long)s.frameBytes, (unsigned long)s.wireBytes,
                  (unsigned long)s.payloadBytes, (unsigned long)s.crcErrors,
                  (unsigned long)s.frameErrors, (unsigned long)s.seqGaps,
                  (unsigned long)s.duplicates, (unsigned long)s.outOfOrder,
                  frameRate, wireKbps, payloadKbps, utilization, efficiencyText,
                  (unsigned long)a.capacityMisses, (unsigned long)a.matched, (unsigned long)a.timeouts, pdrText,
                  averageText,
                  (unsigned long)(a.matched ? a.minUs : 0), (unsigned long)a.maxUs,
                  jitterText);
  }
  Serial.printf("{\"event\":\"summary\",\"matched_acks\":%lu,\"ack_timeouts\":%lu,"
                "\"avg_latency_us\":%.2f}\n",
                (unsigned long)(ackForSource[0].matched + ackForSource[1].matched),
                (unsigned long)(ackForSource[0].timeouts + ackForSource[1].timeouts),
                (ackForSource[0].matched + ackForSource[1].matched) ?
                (ackForSource[0].sumUs + ackForSource[1].sumUs) /
                (ackForSource[0].matched + ackForSource[1].matched) : 0);
}

void setup() {
  Serial.begin(PC_BAUD);
  delay(400);
  Serial.println("{\"event\":\"ready\",\"device\":\"ESP32 passive UART analyzer v2\","
                 "\"line1_rx\":16,\"line2_rx\":27,\"usb_baud\":921600,"
                 "\"format\":\"8N1\",\"autobaud\":true}");
  lastReportMs = millis();
  requests = xQueueCreate(2, sizeof(uint8_t));
  results = xQueueCreate(2, sizeof(Detection));
  if (!requests || !results || xTaskCreate(detectionWorker, "baud", 4096, nullptr, 1, nullptr) != pdPASS) {
    Serial.println("{\"event\":\"error\",\"error\":\"AUTOBAUD_INIT\"}");
    for (;;) delay(1000);
  }
  requestDetection(0);
  requestDetection(1);
}

void loop() {
  finishDetection();
  if (lines[0].locked) {
    uint16_t budget = 512;
    while (tapA.available() && budget--) readByte(0, (uint8_t)tapA.read());
  }
  if (lines[1].locked) {
    uint16_t budget = 512;
    while (tapB.available() && budget--) readByte(1, (uint8_t)tapB.read());
  }
  uint32_t now = millis();
  if ((uint32_t)(now - lastTimeoutCheckMs) >= 100) {
    lastTimeoutCheckMs = now;
    checkPending();
  }
  // One capture line may detect a new baud independently of the other.
  for (uint8_t i = 0; i < 2; ++i) {
    LineState &s = lines[i];
    if (s.locked && (uint32_t)(now - s.lastValidMs) > LOST_AFTER_MS) {
      s.locked = false;
      Serial.printf("{\"event\":\"baud_lost\",\"line\":%u}\n", i + 1);
    }
    if (!s.locked && !searching[i] && (uint32_t)(now - s.lastAttemptMs) > RETRY_AFTER_MS) {
      requestDetection(i);
    }
  }
  reportStats();
}
