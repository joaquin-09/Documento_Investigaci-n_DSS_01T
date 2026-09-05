# Cifrado Polimórfico OTP para IoT — DSS101 G01T

Implementación funcional del modelo criptográfico propuesto en el artículo
**"Cryptography model to secure IoT device endpoints, based on polymorphic
cipher OTP"** (Bran, Flores y Hernández, Universidad Don Bosco), desarrollado
para la actividad "Documento de investigación" de la asignatura Diseño de
Sistemas de Seguridad en Redes de Datos (DSS101), grupo G01T.

## Escenario utilizado

**Modalidad A — Simulación IoT**, con las siguientes características:

- **Hardware simulado**: 2x ESP32 DevKit V1, cada uno en un proyecto de
  [Wokwi](https://wokwi.com) independiente.
- **Comunicación**: WiFi (red virtual `Wokwi-GUEST` de Wokwi, con salida
  real a internet) + protocolo **MQTT** sobre un broker público
  (`broker.hivemq.com`), ya que dos simulaciones de Wokwi independientes no
  comparten red local entre sí, pero sí pueden alcanzar un broker externo.
- **Roles**: Nodo A actúa como iniciador/cliente (dispara el primer
  contacto y los mensajes de prueba); Nodo B actúa como receptor/servidor
  (espera el contacto y responde).

## Resumen del algoritmo implementado

- **Trama del mensaje**: `ID | Type | Payload | PSN`, según lo definido en
  el paper.
- **4 tipos de mensaje**:
  - `FCM` (First Contact Message): intercambia en claro los parámetros
    P, Q y S para construir la tabla de llaves.
  - `RM` (Regular Message): mensaje de datos cifrado.
  - `KUM` (Key Update Message): renueva la tabla de llaves con una nueva
    semilla, sin reiniciar la conexión.
  - `LCM` (Last Contact Message): cierra la sesión y borra las tablas.
- **Generación de llaves de 64 bits**: tres funciones `fs`, `fg` y `fm`
  que, a partir de P, Q y S, generan de forma determinista (ambos nodos
  llegan a la misma tabla sin transmitir las llaves) una tabla de 8 llaves
  de 64 bits.
- **Cifrado polimórfico**: el PSN de cada mensaje selecciona qué llave de
  la tabla usar y en qué orden aplicar 3 de 4 funciones reversibles
  disponibles (XOR, suma, rotación de bits, intercambio de nibbles). El
  PSN del siguiente mensaje se deriva del contenido del mensaje actual,
  haciendo el proceso no determinista frente a un atacante externo.

## Diagrama Wokwi (`diagram.json`, igual para ambos nodos)

```json
{
  "version": 1,
  "author": "G01T",
  "editor": "wokwi",
  "parts": [
    { "type": "wokwi-esp32-devkit-v1", "id": "esp32", "top": 0, "left": 0, "attrs": {} }
  ],
  "connections": [
    [ "esp32:TX0", "$serialMonitor:RX", "", [] ],
    [ "esp32:RX0", "$serialMonitor:TX", "", [] ]
  ]
}
```

## Código completo — Nodo A (iniciador / cliente)

```cpp
/*
  DSS101 - G01T
  "Implementación de algoritmo de cifrado polimórfico" (OTP para IoT)
  NODO A (iniciador del contacto - cliente)

  Basado en: Bran, Flores, Hernández -
  "Cryptography model to secure IoT device endpoints, based on polymorphic cipher OTP"

  Requiere la librería "PubSubClient" (Nick O'Leary) - agrégala desde el
  Library Manager del editor de Wokwi (icono de libro) o desde Arduino IDE.
*/

#include <WiFi.h>
#include <PubSubClient.h>

// ---------- CONFIG WIFI / MQTT ----------
const char* ssid       = "Wokwi-GUEST";
const char* mqttServer = "broker.hivemq.com";
const int   mqttPort   = 1883;

// Cambiar "g01t" por el identificador real de su grupo para no chocar
// con otros equipos que usen el mismo broker público.s
const char* topicAtoB = "dss101/g01t/aTob";   // A publica aqui
const char* topicBtoA = "dss101/g01t/bToa";   // A escucha aqui

WiFiClient espClient;
PubSubClient mqtt(espClient);

// ---------- IDENTIFICADORES DE LA TRAMA ----------
#define NODE_ID   0x01   // ID de este nodo (A)
#define TYPE_FCM  0x00   // First Contact Message
#define TYPE_RM   0x01   // Regular Message
#define TYPE_KUM  0x02   // Key Update Message
#define TYPE_LCM  0x03   // Last Contact Message

// ---------- ESTADO CRIPTOGRAFICO ----------
typedef uint64_t u64;
#define NUM_KEYS 8
u64 keyTable[NUM_KEYS];
u64 P, Q, S;              // parámetros compartidos por el par
uint8_t psn = 0;          // Polymorphic Sequence Nibble actual

enum EstadoNodo { ESPERANDO_SYNC, SINCRONIZADO, CERRADO };
EstadoNodo estado = ESPERANDO_SYNC;

unsigned long ultimoEnvio = 0;
int contadorRM = 0;

// ================= A. GENERACION DE LA TABLA DE LLAVES (fs, fg, fm) =================
// El paper deja fs/fg/fm como "funciones ligeras" sin fórmula fija; aquí se
// implementan como mezcladores tipo splitmix64 (deterministas y con buen
// avalanche), documentado así en el informe.
u64 fs(u64 x, u64 y) {                 // función de mezcla (scrambled): prima+seed -> llave embrión
  u64 v = x ^ y;
  v = (v << 13) | (v >> (64 - 13));
  v *= 0x9E3779B97F4A7C15ULL;
  return v;
}
u64 fg(u64 x, u64 y) {                 // función de generación: embrión+prima -> llave real
  u64 v = x + y;
  v ^= (v >> 30);
  v *= 0xBF58476D1CE4E5B9ULL;
  v ^= (v >> 27);
  return v;
}
u64 fm(u64 x, u64 y) {                 // función de mutación: seed+prima -> nueva seed
  u64 v = x ^ y;
  v = (v << 17) | (v >> (64 - 17));
  v += 0x94D049BB133111EBULL;
  return v;
}

// Algoritmo de la Fig. 3 del paper: alterna P y Q como base en cada ronda
// hasta llenar la tabla con NUM_KEYS llaves de 64 bits.
void generarTablaLlaves(u64 p, u64 q, u64 s) {
  u64 curP = p, curQ = q, curS = s;
  u64 P0, Q0;
  int i = 0;
  while (i < NUM_KEYS) {
    P0 = fs(curP, curS);
    keyTable[i++] = fg(P0, curQ);
    curS = fm(curS, curQ);
    if (i >= NUM_KEYS) break;
    Q0 = fs(curQ, curS);
    keyTable[i++] = fg(Q0, P0);
    curS = fm(curS, P0);
  }
  Serial.println("[CRYPTO] Tabla de llaves (64 bits) generada.");
}

// ================= B. POOL DE FUNCIONES REVERSIBLES (cifrado polimórfico) =================
typedef void (*FrFunc)(uint8_t*, size_t, u64);

void fr_xor(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] ^= kb[i % 8]; }
void fr_add(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(d[i] + kb[i % 8]); }
void fr_sub(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(d[i] - kb[i % 8]); }
void fr_rotl(uint8_t* d, size_t n, u64 k) { int s = (k % 7) + 1; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] << s) | (d[i] >> (8 - s))); }
void fr_rotr(uint8_t* d, size_t n, u64 k) { int s = (k % 7) + 1; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] >> s) | (d[i] << (8 - s))); }
void fr_swap(uint8_t* d, size_t n, u64 k) { for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] << 4) | (d[i] >> 4)); } // auto-inversa

FrFunc encFuncs[4] = { fr_xor, fr_add, fr_rotl, fr_swap };
FrFunc decFuncs[4] = { fr_xor, fr_sub, fr_rotr, fr_swap };  // inversas, mismo índice

// 16 secuencias (una por valor de PSN de 4 bits) que fijan el orden de aplicación
const uint8_t psnSeq[16][3] = {
  {0,1,2}, {1,2,3}, {2,3,0}, {3,0,1},
  {0,2,1}, {1,3,2}, {2,0,3}, {3,1,0},
  {0,1,3}, {1,2,0}, {2,3,1}, {3,0,2},
  {0,3,1}, {1,0,2}, {2,1,3}, {3,2,0}
};

void cifrar(uint8_t* data, size_t len, uint8_t p) {
  u64 key = keyTable[p % NUM_KEYS];
  const uint8_t* seq = psnSeq[p % 16];
  for (int i = 0; i < 3; i++) encFuncs[seq[i]](data, len, key);
}
void descifrar(uint8_t* data, size_t len, uint8_t p) {
  u64 key = keyTable[p % NUM_KEYS];
  const uint8_t* seq = psnSeq[p % 16];
  for (int i = 2; i >= 0; i--) decFuncs[seq[i]](data, len, key);
}

// El PSN del siguiente mensaje depende del contenido (actúa como puntero),
// tal como lo describe la sección del paper sobre el PSN.
uint8_t siguientePSN(uint8_t* dataPlano, size_t len, uint8_t psnActual) {
  if (len == 0) return (psnActual + 1) % 16;
  return dataPlano[psnActual % len] % 16;
}

// ================= TRAMA: ID | TYPE | LEN | PAYLOAD | PSN =================
int construirTrama(uint8_t id, uint8_t type, uint8_t* payload, uint8_t len, uint8_t p, uint8_t* out) {
  out[0] = id; out[1] = type; out[2] = len;
  memcpy(&out[3], payload, len);
  out[3 + len] = p;
  return 4 + len;
}
bool parsearTrama(uint8_t* buf, int totalLen, uint8_t &id, uint8_t &type, uint8_t* payloadOut, uint8_t &len, uint8_t &p) {
  if (totalLen < 4) return false;
  id = buf[0]; type = buf[1]; len = buf[2];
  if (totalLen < 4 + len) return false;
  memcpy(payloadOut, &buf[3], len);
  p = buf[3 + len];
  return true;
}

// ================= HEX HELPERS PARA MQTT =================
void bytesToHex(uint8_t* data, size_t len, char* out) {
  const char* hx = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++) {
    out[i*2]   = hx[(data[i] >> 4) & 0xF];
    out[i*2+1] = hx[data[i] & 0xF];
  }
  out[len*2] = '\0';
}
int hexToBytes(const char* hex, size_t hlen, uint8_t* out, size_t maxLen) {
  size_t n = hlen / 2;
  if (n > maxLen) n = maxLen;
  for (size_t i = 0; i < n; i++) {
    char b[3] = { hex[i*2], hex[i*2+1], 0 };
    out[i] = (uint8_t) strtol(b, NULL, 16);
  }
  return n;
}

// ================= ENVIO DE MENSAJES =================
void enviarMensaje(uint8_t type, uint8_t* payload, uint8_t len, uint8_t p) {
  uint8_t trama[64];
  int tramaLen = construirTrama(NODE_ID, type, payload, len, p, trama);
  char hex[130];
  bytesToHex(trama, tramaLen, hex);
  mqtt.publish(topicAtoB, hex);
}

u64 semillaAleatoria() {
  // Combina ruido analógico + micros() como fuente de entropía (equivalente a
  // los "parámetros físicos del núcleo IoT" que menciona el paper).
  u64 v = 0;
  for (int i = 0; i < 8; i++) {
    v = (v << 8) | (analogRead(34) ^ (micros() & 0xFF));
    delayMicroseconds(50);
  }
  return v;
}

// ================= CALLBACK MQTT (mensajes que llegan de B) =================
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  uint8_t raw[130];
  int rawLen = hexToBytes((const char*)payload, length, raw, sizeof(raw));

  uint8_t id, type, len, pRecibido;
  uint8_t datos[64];
  if (!parsearTrama(raw, rawLen, id, type, datos, len, pRecibido)) return;

  if (type == TYPE_FCM && estado == ESPERANDO_SYNC) {
    Serial.println("[A] FCM-ACK recibido de B. Nodos sincronizados.");
    estado = SINCRONIZADO;
    psn = 0;
  }
  else if (type == TYPE_RM && estado == SINCRONIZADO) {
    uint8_t copia[64];
    memcpy(copia, datos, len);
    descifrar(copia, len, pRecibido);
    copia[len] = '\0';
    Serial.print("[A] RM recibido y descifrado de B: ");
    Serial.println((char*)copia);
    psn = siguientePSN(copia, len, pRecibido);
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== NODO A (iniciador) ===");

  WiFi.begin(ssid, "", 6);
  Serial.print("Conectando WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(200); Serial.print("."); }
  Serial.print("\nWiFi OK, IP: "); Serial.println(WiFi.localIP());

  mqtt.setServer(mqttServer, mqttPort);
  mqtt.setCallback(onMqttMessage);
  while (!mqtt.connected()) {
    Serial.print("Conectando MQTT...");
    if (mqtt.connect("esp32-nodeA")) {
      Serial.println("OK");
      mqtt.subscribe(topicBtoA);
    } else {
      Serial.println("reintentando...");
      delay(1000);
    }
  }

  // --- FCM: generar P, Q, S y enviarlos en claro para iniciar el par ---
  P = semillaAleatoria();
  Q = semillaAleatoria();
  S = semillaAleatoria();
  generarTablaLlaves(P, Q, S);

  uint8_t payload[24];
  memcpy(&payload[0],  &P, 8);
  memcpy(&payload[8],  &Q, 8);
  memcpy(&payload[16], &S, 8);
  enviarMensaje(TYPE_FCM, payload, 24, 0);
  Serial.println("[A] FCM enviado (P, Q, S).");

  ultimoEnvio = millis();
}

// ================= LOOP =================
void loop() {
  if (!mqtt.connected()) {
    if (mqtt.connect("esp32-nodeA")) mqtt.subscribe(topicBtoA);
    delay(500);
    return;
  }
  mqtt.loop();

  // Cada 5s, si ya estamos sincronizados, mandamos un mensaje de prueba
  if (estado == SINCRONIZADO && millis() - ultimoEnvio > 5000) {
    ultimoEnvio = millis();

    char msg[32];
    snprintf(msg, sizeof(msg), "Sensor:%d", contadorRM);
    uint8_t datos[32];
    size_t msgLen = strlen(msg);
    memcpy(datos, msg, msgLen);

    if (contadorRM == 3) {
      // Disparamos un KUM: nueva semilla, mismas P y Q
      S = semillaAleatoria();
      generarTablaLlaves(P, Q, S);
      uint8_t nuevaS[8];
      memcpy(nuevaS, &S, 8);
      enviarMensaje(TYPE_KUM, nuevaS, 8, psn);
      Serial.println("[A] KUM enviado (nueva semilla, tabla regenerada).");
      psn = 0;
    }
    else if (contadorRM == 6) {
      uint8_t vacio[1] = {0};
      enviarMensaje(TYPE_LCM, vacio, 0, psn);
      Serial.println("[A] LCM enviado. Cerrando sesion.");
      estado = CERRADO;
    }
    else {
      uint8_t copia[32];
      memcpy(copia, datos, msgLen);
      cifrar(copia, msgLen, psn);
      enviarMensaje(TYPE_RM, copia, msgLen, psn);
      Serial.print("[A] RM enviado (cifrado con PSN="); Serial.print(psn);
      Serial.print("), original: "); Serial.println(msg);
      psn = siguientePSN(datos, msgLen, psn);
    }
    contadorRM++;
  }
}

```

## Código completo — Nodo B (receptor / servidor)

```cpp
/*
  DSS101 - G01T
  "Implementación de algoritmo de cifrado polimórfico" (OTP para IoT)
  NODO B (receptor - servidor)

  Basado en: Bran, Flores, Hernández -
  "Cryptography model to secure IoT device endpoints, based on polymorphic cipher OTP"

  IMPORTANTE: toda la lógica criptográfica (fs, fg, fm, pool de funciones
  reversibles, trama, PSN) debe ser IDÉNTICA a la del Nodo A. Solo cambian
  el NODE_ID, los tópicos MQTT y el rol dentro de la máquina de estados.

  Requiere la librería "PubSubClient" (Nick O'Leary) - agrégala desde el
  Library Manager del editor de Wokwi (icono de libro) o desde Arduino IDE.
*/

#include <WiFi.h>
#include <PubSubClient.h>

// ---------- CONFIG WIFI / MQTT ----------
const char* ssid       = "Wokwi-GUEST";
const char* mqttServer = "broker.hivemq.com";
const int   mqttPort   = 1883;

// Deben coincidir EXACTAMENTE con los del Nodo A (mismo grupo).
const char* topicAtoB = "dss101/g01t/aTob";   // B escucha aqui
const char* topicBtoA = "dss101/g01t/bToa";   // B publica aqui

WiFiClient espClient;
PubSubClient mqtt(espClient);

// ---------- IDENTIFICADORES DE LA TRAMA ----------
#define NODE_ID   0x02   // ID de este nodo (B)
#define TYPE_FCM  0x00
#define TYPE_RM   0x01
#define TYPE_KUM  0x02
#define TYPE_LCM  0x03

// ---------- ESTADO CRIPTOGRAFICO ----------
typedef uint64_t u64;
#define NUM_KEYS 8
u64 keyTable[NUM_KEYS];
u64 P, Q, S;
uint8_t psn = 0;

enum EstadoNodo { ESPERANDO_SYNC, SINCRONIZADO, CERRADO };
EstadoNodo estado = ESPERANDO_SYNC;

// ================= A. GENERACION DE LA TABLA DE LLAVES (fs, fg, fm) =================
u64 fs(u64 x, u64 y) {
  u64 v = x ^ y;
  v = (v << 13) | (v >> (64 - 13));
  v *= 0x9E3779B97F4A7C15ULL;
  return v;
}
u64 fg(u64 x, u64 y) {
  u64 v = x + y;
  v ^= (v >> 30);
  v *= 0xBF58476D1CE4E5B9ULL;
  v ^= (v >> 27);
  return v;
}
u64 fm(u64 x, u64 y) {
  u64 v = x ^ y;
  v = (v << 17) | (v >> (64 - 17));
  v += 0x94D049BB133111EBULL;
  return v;
}

void generarTablaLlaves(u64 p, u64 q, u64 s) {
  u64 curP = p, curQ = q, curS = s;
  u64 P0, Q0;
  int i = 0;
  while (i < NUM_KEYS) {
    P0 = fs(curP, curS);
    keyTable[i++] = fg(P0, curQ);
    curS = fm(curS, curQ);
    if (i >= NUM_KEYS) break;
    Q0 = fs(curQ, curS);
    keyTable[i++] = fg(Q0, P0);
    curS = fm(curS, P0);
  }
  Serial.println("[CRYPTO] Tabla de llaves (64 bits) generada.");
}

// ================= B. POOL DE FUNCIONES REVERSIBLES (cifrado polimórfico) =================
typedef void (*FrFunc)(uint8_t*, size_t, u64);

void fr_xor(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] ^= kb[i % 8]; }
void fr_add(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(d[i] + kb[i % 8]); }
void fr_sub(uint8_t* d, size_t n, u64 k)  { uint8_t* kb = (uint8_t*)&k; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(d[i] - kb[i % 8]); }
void fr_rotl(uint8_t* d, size_t n, u64 k) { int s = (k % 7) + 1; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] << s) | (d[i] >> (8 - s))); }
void fr_rotr(uint8_t* d, size_t n, u64 k) { int s = (k % 7) + 1; for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] >> s) | (d[i] << (8 - s))); }
void fr_swap(uint8_t* d, size_t n, u64 k) { for (size_t i = 0; i < n; i++) d[i] = (uint8_t)((d[i] << 4) | (d[i] >> 4)); }

FrFunc encFuncs[4] = { fr_xor, fr_add, fr_rotl, fr_swap };
FrFunc decFuncs[4] = { fr_xor, fr_sub, fr_rotr, fr_swap };

const uint8_t psnSeq[16][3] = {
  {0,1,2}, {1,2,3}, {2,3,0}, {3,0,1},
  {0,2,1}, {1,3,2}, {2,0,3}, {3,1,0},
  {0,1,3}, {1,2,0}, {2,3,1}, {3,0,2},
  {0,3,1}, {1,0,2}, {2,1,3}, {3,2,0}
};

void cifrar(uint8_t* data, size_t len, uint8_t p) {
  u64 key = keyTable[p % NUM_KEYS];
  const uint8_t* seq = psnSeq[p % 16];
  for (int i = 0; i < 3; i++) encFuncs[seq[i]](data, len, key);
}
void descifrar(uint8_t* data, size_t len, uint8_t p) {
  u64 key = keyTable[p % NUM_KEYS];
  const uint8_t* seq = psnSeq[p % 16];
  for (int i = 2; i >= 0; i--) decFuncs[seq[i]](data, len, key);
}

uint8_t siguientePSN(uint8_t* dataPlano, size_t len, uint8_t psnActual) {
  if (len == 0) return (psnActual + 1) % 16;
  return dataPlano[psnActual % len] % 16;
}

// ================= TRAMA: ID | TYPE | LEN | PAYLOAD | PSN =================
int construirTrama(uint8_t id, uint8_t type, uint8_t* payload, uint8_t len, uint8_t p, uint8_t* out) {
  out[0] = id; out[1] = type; out[2] = len;
  memcpy(&out[3], payload, len);
  out[3 + len] = p;
  return 4 + len;
}
bool parsearTrama(uint8_t* buf, int totalLen, uint8_t &id, uint8_t &type, uint8_t* payloadOut, uint8_t &len, uint8_t &p) {
  if (totalLen < 4) return false;
  id = buf[0]; type = buf[1]; len = buf[2];
  if (totalLen < 4 + len) return false;
  memcpy(payloadOut, &buf[3], len);
  p = buf[3 + len];
  return true;
}

// ================= HEX HELPERS PARA MQTT =================
void bytesToHex(uint8_t* data, size_t len, char* out) {
  const char* hx = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++) {
    out[i*2]   = hx[(data[i] >> 4) & 0xF];
    out[i*2+1] = hx[data[i] & 0xF];
  }
  out[len*2] = '\0';
}
int hexToBytes(const char* hex, size_t hlen, uint8_t* out, size_t maxLen) {
  size_t n = hlen / 2;
  if (n > maxLen) n = maxLen;
  for (size_t i = 0; i < n; i++) {
    char b[3] = { hex[i*2], hex[i*2+1], 0 };
    out[i] = (uint8_t) strtol(b, NULL, 16);
  }
  return n;
}

// ================= ENVIO DE MENSAJES =================
void enviarMensaje(uint8_t type, uint8_t* payload, uint8_t len, uint8_t p) {
  uint8_t trama[64];
  int tramaLen = construirTrama(NODE_ID, type, payload, len, p, trama);
  char hex[130];
  bytesToHex(trama, tramaLen, hex);
  mqtt.publish(topicBtoA, hex);
}

// ================= CALLBACK MQTT (mensajes que llegan de A) =================
void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  uint8_t raw[130];
  int rawLen = hexToBytes((const char*)payload, length, raw, sizeof(raw));

  uint8_t id, type, len, pRecibido;
  uint8_t datos[64];
  if (!parsearTrama(raw, rawLen, id, type, datos, len, pRecibido)) return;

  if (type == TYPE_FCM && estado == ESPERANDO_SYNC) {
    // Primer contacto: A envía P, Q, S en claro (24 bytes)
    memcpy(&P, &datos[0], 8);
    memcpy(&Q, &datos[8], 8);
    memcpy(&S, &datos[16], 8);
    generarTablaLlaves(P, Q, S);
    estado = SINCRONIZADO;
    psn = 0;
    Serial.println("[B] FCM recibido de A. Tabla de llaves construida. Sincronizado.");

    // Confirmamos a A que ya estamos listos (FCM-ACK, payload vacío)
    uint8_t vacio[1] = {0};
    enviarMensaje(TYPE_FCM, vacio, 0, 0);
  }
  else if (type == TYPE_RM && estado == SINCRONIZADO) {
    uint8_t copia[64];
    memcpy(copia, datos, len);
    descifrar(copia, len, pRecibido);
    copia[len] = '\0';
    Serial.print("[B] RM recibido y descifrado de A: ");
    Serial.println((char*)copia);

    // Verificación de integridad: comprobamos que el contenido tenga el
    // formato esperado "Sensor:N" (evidencia de recuperación correcta)
    if (strncmp((char*)copia, "Sensor:", 7) == 0) {
      Serial.println("[B] Verificacion OK: mensaje recuperado coincide con el formato esperado.");
    }

    psn = siguientePSN(copia, len, pRecibido);
  }
  else if (type == TYPE_KUM && estado == SINCRONIZADO) {
    memcpy(&S, datos, 8);   // nueva semilla, P y Q se mantienen
    generarTablaLlaves(P, Q, S);
    psn = 0;
    Serial.println("[B] KUM recibido. Tabla de llaves regenerada con nueva semilla.");
  }
  else if (type == TYPE_LCM) {
    Serial.println("[B] LCM recibido. Cerrando sesion y liberando tabla de llaves.");
    estado = CERRADO;
    memset(keyTable, 0, sizeof(keyTable));
  }
}

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("=== NODO B (receptor) ===");

  WiFi.begin(ssid, "", 6);
  Serial.print("Conectando WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(200); Serial.print("."); }
  Serial.print("\nWiFi OK, IP: "); Serial.println(WiFi.localIP());

  mqtt.setServer(mqttServer, mqttPort);
  mqtt.setCallback(onMqttMessage);
  while (!mqtt.connected()) {
    Serial.print("Conectando MQTT...");
    if (mqtt.connect("esp32-nodeB")) {
      Serial.println("OK");
      mqtt.subscribe(topicAtoB);
      Serial.println("[B] Esperando FCM de A...");
    } else {
      Serial.println("reintentando...");
      delay(1000);
    }
  }
}

// ================= LOOP =================
void loop() {
  if (!mqtt.connected()) {
    if (mqtt.connect("esp32-nodeB")) mqtt.subscribe(topicAtoB);
    delay(500);
    return;
  }
  mqtt.loop();
}

```

## Instrucciones de ejecución

1. Crear dos proyectos nuevos en [wokwi.com](https://wokwi.com) a partir
   de la plantilla **"ESP32"** (uno para el Nodo A, otro para el Nodo B).
2. En cada proyecto, reemplazar el contenido de `diagram.json` por el
   mostrado arriba (es igual para ambos nodos).
3. En cada proyecto, agregar la librería **PubSubClient** (Nick O'Leary)
   desde el Library Manager del editor (ícono de libro 📖 → buscar
   "PubSubClient" → Add).
4. Copiar el código del **Nodo A** (arriba) en el `sketch.ino` de un
   proyecto, y el código del **Nodo B** en el `sketch.ino` del otro.
5. Ejecutar **primero** el proyecto del Nodo B (Run ▶️) y esperar a que
   en su Serial Monitor aparezca `Esperando FCM de A...`. Recién entonces
   ejecutar el proyecto del Nodo A.
6. Mantener ambas pestañas del navegador visibles (no minimizadas), ya
   que el navegador ralentiza la simulación de una pestaña en segundo
   plano.
7. Observar en ambos Serial Monitor el intercambio completo: FCM →
   sincronización → mensajes RM cifrados/descifrados → KUM (renovación de
   llaves) → LCM (cierre de sesión). El ciclo completo tarda
   aproximadamente 35-40 segundos desde la sincronización.

> **Nota:** si se corre en paralelo con otros equipos usando el mismo
> broker público, cambien el identificador de grupo (`g01t`) dentro de
> los tópicos MQTT (`topicAtoB` / `topicBtoA`) en ambos archivos, para
> evitar que sus mensajes se mezclen con los de otro grupo.

## Enlace de la simulación

Proyectos de Wokwi (uno por nodo):

- **Nodo A:** https://wokwi.com/projects/474187392633936897
- **Nodo B:** https://wokwi.com/projects/474189269611593729

Video demostrativo de la simulación funcionando (ambos nodos, Serial
Monitor en paralelo, ciclo completo FCM → RM → KUM → LCM):

**https://youtu.be/sImWh06x6uE**

## Autores

| Nombre | Carnet |
|---|---|
| Joaquín Morán | MM230272 |
| Rodrigo Mejía | MR230247 |
| André Preza | PD230540 |
| Bryan Fuente | FM230331 |