# Listener FortiSIEM (XML → JSON)

Script: `fortisiem-listener/fortisiem_listener.py`

## Motivo

FortiSIEM emite sus incidentes por syslog en formato **XML** (a veces embebido dentro
de un mensaje CEF con un campo `rawEvent=`). Wazuh no tiene un decoder nativo confiable
para XML anidado, y escribir uno en PCRE2 sería frágil y difícil de mantener frente a
cambios en la estructura del XML. La solución fue desacoplar el *parsing* del XML del
propio Wazuh usando un servicio Python dedicado.

## Configuración (variables de entorno)

| Variable | Default | Descripción |
|---|---|---|
| `FSIEM_LISTEN_HOST` | `0.0.0.0` | Interfaz de escucha |
| `FSIEM_LISTEN_PORT` | `5555` | Puerto UDP de escucha |
| `FSIEM_OUTPUT_FILE` | `/var/log/fortisiem/fortisiem.json` | Archivo de salida que consume Wazuh |
| `FSIEM_ERROR_LOG` | `/var/log/fortisiem/listener_errors.log` | Log de errores del propio listener (no de FortiSIEM) |
| `FSIEM_MAX_FILE_MB` | `100` | Tamaño máximo antes de rotar |
| `FSIEM_BACKUP_COUNT` | `5` | Cantidad de backups a conservar |

## Pipeline interno (`process_message`)

1. **`parse_syslog_header`**: extrae timestamp y IP de origen del encabezado syslog
   estándar (`Jun 16 15:35:33 <ip> ...`).
2. **`extract_xml_from_syslog`**: soporta dos formatos:
   - XML directo: busca el bloque `<event ...>...</event>`.
   - CEF con XML embebido: busca `rawEvent=...` y dentro de ese contenido el
     `<event>...</event>`.
3. **`xml_element_to_dict`**: convierte el árbol XML a diccionario de forma recursiva,
   preservando atributos (prefijados con `@`) y limpiando nombres de tag con prefijo
   `_` (ej. `_ruleName` → `ruleName`).
4. **`normalize_event`**: enriquece el evento:
   - Etiqueta `severity_label` (`low`/`medium`/`high`/`critical`) a partir de
     `eventSeverity`.
   - Convierte `attackTechniqueId`, `incidentRptIp`, `incidentRptDevName` de string
     separado por comas a listas.
   - Resume `triggerEventLists` (evita guardar IDs de evento larguísimos, solo cuenta
     y tipos), para no inflar el tamaño del JSON final.
5. **`write_json_line`**: serializa con `json.dumps` y escribe una línea por evento en
   el archivo rotado (`RotatingFileHandler`), que es exactamente lo que Wazuh espera
   con `log_format=json`.

## Despliegue como servicio (systemd)

```ini
# /etc/systemd/system/fortisiem-listener.service
[Unit]
Description=FortiSIEM XML-to-JSON Syslog Listener
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/fortisiem-listener/fortisiem_listener.py
Restart=always
RestartSec=5
User=root
Environment=FSIEM_LISTEN_PORT=5555
Environment=FSIEM_OUTPUT_FILE=/var/log/fortisiem/fortisiem.json

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now fortisiem-listener
```

## Configuración correspondiente en `ossec.conf`

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/fortisiem/fortisiem.json</location>
  <label key="source">fortisiem</label>
</localfile>
```

El `<label key="source">fortisiem</label>` es lo que permite que la regla `190102`
(`fortisiem.xml`) filtre por `field name="source"`.
