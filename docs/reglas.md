# Reglas de correlación

## FortiGate (`OverwriteRules.xml`)

| ID | Nivel | Condición | Descripción |
|---|---|---|---|
| 100050 | 0 | `if_sid=592` + regex sobre ruta de log de FortiGate | Silencia el ruido de "reducción de tamaño de log" |
| 100300 | 12 | `if_sid=81629` + `crlevel=critical` | IPS crítico |
| 100301 | 12 | `if_sid=81629` + `crlevel=high` | IPS alto |
| 100302 | 10 | `if_sid=81629` + `crlevel=medium` | IPS medio |
| 100303 | 12 | `if_sid=81612` | Cambio de configuración (edit) en el equipo |

`81629`/`81612` son SIDs nativos del decoder de FortiGate incluido por defecto en Wazuh;
aquí solo se sobreescribe/asciende su nivel y se enriquece la descripción.

## FortiWeb (`fortiweb.xml`)

- **100990** (nivel 3): regla base — todo evento decodificado como `fortiweb` cae aquí,
  sirve como almacenamiento/baseline para poder perfilar tráfico normal.
- **100992** (nivel 13): sube a alerta crítica cuando `severity_level=High`, excluyendo
  explícitamente el subtipo `Cookie Signed Verification Failed` (negate) porque genera
  demasiados falsos positivos ruidosos.

## Darktrace (`darktrace.xml`)

- **100100** (nivel 10): regla genérica única — cualquier evento decodificado como
  `darktrace-cef` genera alerta, usando `$(dark_description)` como texto.

## FortiSIEM (`fortisiem.xml`)

- **190102** (nivel 13): dispara cuando `source=fortisiem` y `eventSeverity` es 8, 9 o 10
  (incidentes de severidad alta/crítica reportados por FortiSIEM).

## Banca Digital (`BancaDigital.xml`)

### Reglas base de almacenamiento (nivel 3)
`110200` (login), `110201` (pago QR), `110202` (lectura QR), `110203` (generación OTP).
Sirven como "hechos" sobre los que luego se corren las reglas de correlación con
`if_matched_sid` / `if_sid`.

### Reglas de alerta (grupo `banca_digital_alertas`)

| ID | Nivel | Caso de uso | Lógica |
|---|---|---|---|
| 110210 | 5 | Login fallido | `BDigitalLogType=response` + `"success":false` |
| 110211 | 10 | Fuerza bruta por usuario | ≥10 fallos (110210) al mismo `BDigitalUserName` en 120s |
| 110212 | 12 | Fuerza bruta por IP | ≥10 fallos (110210) desde la misma IP en 300s |
| 110222 | 8 | Velocidad de pagos QR sospechosa | ≥5 pagos QR (110201) del mismo usuario en 180s |
| 110223 | 8 | Abuso de generación de OTP | ≥4 OTP (110203) del mismo usuario en 300s |
| 110224 | 14 | Posible *account takeover* | 2 logins exitosos (110200) del mismo usuario desde **distintas IPs** en 600s |
| 110225 | 11 | *Credential stuffing* | Misma IP intenta loguearse con >5 usuarios distintos en 180s |
| 110226 | 10 | Login exitoso desde país extranjero | `success:true` + `srcgeoip != BO` |
| 110227 | 7 | Pagos repetidos al mismo destino | ≥3 pagos (110201) a la misma `BDigitalTargetAccount` en 600s |
| 110221 | 10 | Transacción de monto muy alto | `BDigitalAmount` matchea patrón de montos ≥ ~9000+ (ver nota) |
| 110229 | 6 | Encadenamiento OTP + pago alto monto | Sigue a 110223 dentro de 60s del mismo usuario |

> **Nota sobre 110221:** el archivo original documenta con comentarios `XDDD` que esta
> regla y la 110212 (fuerza bruta por IP) todavía están en revisión/pruebas — quedó
> anotado tal cual para que quede constancia de que son reglas en maduración, no
> definitivas. Vale la pena documentarlo también en el informe para el docente como
> parte del proceso iterativo de ajuste de reglas (reducción de falsos positivos).

### Diseño general de las reglas de Banca Digital

- Se usa el patrón **regla base (nivel 3, "hecho") + reglas de correlación
  (`if_matched_sid`)** en vez de reglas monolíticas, lo que permite reutilizar el mismo
  evento base (ej. login fallido) en varias reglas de detección distintas (fuerza
  bruta por usuario, por IP, credential stuffing) sin duplicar el decoder.
- Se usan los modificadores de correlación nativos de Wazuh: `same_field`,
  `same_srcip`, `different_srcip`, `different_field`, `frequency` + `timeframe`, lo que
  permite modelar comportamiento temporal (ventanas deslizantes) sin necesidad de un
  motor de correlación externo.
