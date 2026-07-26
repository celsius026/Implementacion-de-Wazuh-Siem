# Arquitectura de la solución

## 1. Flujo general de datos

1. **Ingesta**: cada fuente envía sus logs por syslog (UDP/TCP) o queda expuesta como
   archivo local que Wazuh lee con `<localfile>`.
2. **Caso especial — FortiSIEM**: FortiSIEM no permite un formato de log fácilmente
   decodificable de forma nativa por Wazuh (emite XML embebido en syslog/CEF). Por eso
   se desarrolló un **listener Python independiente** (`fortisiem_listener.py`) que:
   - Escucha en un puerto UDP dedicado (por defecto `5555`).
   - Extrae el bloque `<event>...</event>` del mensaje syslog (ya sea XML puro o
     embebido dentro de un campo `rawEvent=` en CEF).
   - Convierte el XML a un diccionario Python recursivamente (`xml_element_to_dict`).
   - Normaliza el evento (severidad, listas de IPs/técnicas MITRE, conteo de eventos
     agregados).
   - Escribe cada evento como una línea JSON en `/var/log/fortisiem/fortisiem.json`,
     rotando el archivo automáticamente (`RotatingFileHandler`).
3. **Decodificación**: Wazuh Manager lee cada `<localfile>` o `<remote>` según su
   `log_format` (`syslog`, `json`) y aplica los decoders correspondientes
   (`fortiweb`, `darktrace-cef`, `BancaDigital`, o el decoder JSON nativo para
   FortiSIEM).
4. **Correlación (reglas)**: sobre los campos ya decodificados se aplican reglas de
   nivel 3 (almacenamiento/baseline) y reglas de nivel 5–14 (alertas), usando
   frecuencia/`timeframe`, `same_field`, `same_srcip`, `different_field`, geolocalización,
   etc.
5. **Notificación**: toda alerta con `level >= 9` dispara la integración
   `custom-send-data-to-app.py`, que arma un payload normalizado y lo envía por HTTPS
   con reintentos exponenciales al backend de la app móvil.

## 2. Por qué un listener separado para FortiSIEM

FortiSIEM exporta sus incidentes como XML dentro de mensajes syslog, un formato que los
decoders nativos de Wazuh (pensados para texto plano, JSON o CEF simple) no procesan
bien de forma directa. En vez de escribir un decoder PCRE2 extremadamente frágil para
XML anidado, se optó por:

- Un **proceso auxiliar en Python** que hace de "traductor" (XML → JSON).
- Wazuh consume el resultado como un `<localfile>` con `log_format=json`, que es un
  formato que decodifica de forma nativa y confiable.

Esto separa responsabilidades: el listener se encarga del parsing complejo, y Wazuh solo
decodifica/correla JSON ya limpio.
