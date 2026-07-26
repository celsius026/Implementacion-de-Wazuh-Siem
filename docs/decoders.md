# Decoders

Los decoders viven en `/var/ossec/etc/decoders/` y son los responsables de extraer
campos estructurados desde el log crudo antes de que las reglas puedan usarlos.

## FortiWeb (`fortiweb.xml`)

- **Prematch (decoder padre):** `device_id=FV\w+` — identifica que el log viene de un
  dispositivo FortiWeb por su prefijo de `device_id`.
- **Formato de origen:** log tipo `key=value` (estilo Fortinet), no XML ni JSON.
- **Campos extraídos (decoders hijos, todos con el mismo `parent`):**
  `type`, `subtype`, `proto`, `service`, `status`, `policy`, `srcip`, `src_port`,
  `dstip`, `dst_port`, `http_method`, `http_url`, `http_retcode`, `http_host`,
  `user_name`, `srccountry`, `http_agent`, `date`, `time`, `log_id`, `msg_id`,
  `device_id`, `eventtime`, `vd`, `timezone`, `pri`, `reason`, `original_src`,
  tiempos/tamaños de request-response, `msg`, campos de ML/anti-bot
  (`ml_log_hmm_probability`, `ml_svm_*`, `owasp_top10`, `owasp_api_top10`, `bot_info`,
  `matched_field`, `matched_pattern`, `attack_type`, etc.), y campos de severidad
  (`severity_level`, `threat_level`, `threat_weight`).
- **Nota de diseño:** se usan múltiples decoders "hijos" con el mismo `<parent>fortiweb</parent>`
  en lugar de un único regex gigante. Esto hace que cada campo se pueda extraer de forma
  independiente aunque no todos estén presentes en cada línea (los logs de FortiWeb no
  siempre traen los mismos campos según el `subtype` del evento).

## Darktrace (`Darktrace.xml`)

- **Prematch:** `CEF:\d+\|Darktrace\|` — estándar CEF (Common Event Format).
- **Decoder de cabecera fija:** separa los 5 primeros campos posicionales del CEF
  (`dark_product`, `dark_version`, `dark_event_id`, `dark_description`, `dark_severity`).
- **Campos adicionales (extension CEF, key=value):** `srcip` (mapeado desde `dvc`,
  ya que en Darktrace `dvc` identifica el host implicado y no el origen del log),
  `dark_dstip`, `dark_dvchost`, `dark_dstport`, `dark_url` (`darktraceUrl`),
  `mitre.id` (`mitreId`), `dark_tags`, `dark_srcuser` (`suser`), `dark_mac`
  (desde `deviceMacAddress` o `dmac`), `dark_external_id`, `dark_current_group`,
  `dark_group_category`.
- **Nota importante ya documentada en el archivo original:** el campo `dvc` en Darktrace
  representa el *host local implicado* (lhost), no necesariamente el origen real del
  ataque — hay que tenerlo en cuenta al construir reglas de correlación por IP.

## Banca Digital (`BancaDigital.xml`)

- **Prematch (decoder padre `BancaDigital`):** `CortexAuditWorker ` — logs de auditoría
  del backend transaccional.
- **Un decoder hijo por tipo de servicio** (usando `use_own_name=true` y `prematch` sobre
  el campo `"service":"..."` del JSON), en vez de un único decoder genérico, para poder
  tener nombres de campo (`order`) específicos por caso de uso:
  - `BDigitalLogin` → `"service":"login"`
  - `BDigitalPayQr` → `"service":"pay_qr"`
  - `BDigitalReadQr` → `"service":"read_qr"`
  - `BDigitalGenerateOtp` → `"service":"generate_otp"`
  - `BDigitalAperturaCuenta` → `"service":"apertura_cuenta"`
  - `BDigitalGestionTarjeta` → `"service":"gestion_tarjeta_debito"`
  - `BDigitalCambioContrasenia` → `"service":"cambio_contrase..."`
  - `BDigitalGeneracionOtp` → `"service":"generacion_otp"`
  - `BDigitalPayServices` → `"service":"pay_services"`
  - `BDigitalGenerateQr` → `"service":"generate_qr"`
  - `BDigitalTransferencia` → `"service":"transferencia"`
  - `BDigitalPagoPrestamo` → `"service":"pago_prestamo"`
- **Campos comunes a casi todos:** `srcip`, `BDigitalUserName`, `BDigitalUserId`,
  `BDigitalSessionId`, `BDigitalChannel`, `BDigitalInfoDevice`, `BDigitalDeviceOs`,
  `BDigitalGeoLocation`, `BDigitalCountry`, `BDigitalCity`, `BDigitalSuccess`,
  `BDigitalErrorCode`, `BDigitalErrorMessage`, `BDigitalCreatedAt`.
- **Campos específicos por caso de uso:** montos y cuentas (`BDigitalAmount`,
  `BDigitalOriginAccount`, `BDigitalTargetAccount`), datos de QR (`BDigitalQrId`),
  datos de OTP (`BDigitalHashCode`, `BDigitalFunctionality`), datos de apertura de
  cuenta y tarjetas, etc.

## FortiSIEM (vía `local_decoder.xml` / decoder JSON nativo)

FortiSIEM no tiene un decoder XML propio: el listener custom (ver
`docs/fortisiem-listener.md`) convierte el XML a JSON limpio, y Wazuh lo decodifica con
el decoder JSON genérico (`log_format=json` en `ossec.conf`), etiquetado con
`<label key="source">fortisiem</label>` para poder filtrarlo en reglas por el campo
`source`.
