# Integración con aplicación móvil de alertas

Script: `integrations/custom-send-data-to-app.py`
Registrado en `ossec.conf` como:

```xml
<integration>
   <name>custom-send-data-to-app</name>
   <level>9</level>
   <alert_format>json</alert_format>
 </integration>
```

Esto hace que Wazuh invoque el script automáticamente por cada alerta con
`level >= 9`, pasándole la alerta completa en formato JSON como argumento.

## Configuración (variables de entorno recomendadas)

En vez de hardcodear el endpoint y el token en el código (como en el borrador original),
se recomienda:

```python
import os

ENDPOINT_URL = os.environ["APP_ENDPOINT_URL"]
AUTH_TOKEN   = os.environ["APP_AUTH_TOKEN"]
```

Y definir esas variables en el servicio systemd de Wazuh o en un archivo `/etc/wazuh-integrations.env`
que **no se versiona** (agregado a `.gitignore`).

## Lógica del script

1. **Lectura de la alerta** (`leer_alerta`): recibe la ruta del archivo JSON temporal
   como `sys.argv[1]`.
2. **Filtro de nivel mínimo** (`NIVEL_MINIMO = 9`): doble seguro además del `<level>`
   configurado en `ossec.conf`.
3. **Determinación de criticidad** (`determinar_criticidad`): mapea el `level` numérico
   de Wazuh a una etiqueta legible (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) para la app móvil.
4. **Determinación de fuente** (`determinar_fuente`): cascada de reglas descrita en
   `docs/arquitectura.md`, para etiquetar la alerta como `transacciones`, `fortiweb`,
   `darktrace`, `cloudflare`, `fortisiem` o `wazuh`.
5. **Construcción del payload** (`construir_payload`): arma un JSON normalizado con
   `srcip`, `dstip`, `timestamp`, `title` (descripción de la regla), `origin_log`
   (log crudo completo) y `data_log` (todos los campos de `data` + metadata agregada).
6. **Envío** (`enviar_alerta`): `POST` HTTPS con:
   - Timeout de 10s.
   - Hasta 3 reintentos con backoff exponencial (2s, 4s, 8s).
   - Log de éxito/fallo en `/var/ossec/logs/integrations/custom-app.log`.

## Ejemplo de payload enviado

```json
{
  "data": {
    "srcip": ["10.10.20.15"],
    "event_time": "2026-07-21T10:15:00.000-0400",
    "timestamp": "2026-07-21T10:15:00.000-0400",
    "title": "BancaDigital: Posible fuerza bruta desde ip 10.10.20.15 - mas de 10 logins fallidos",
    "origin_log": ["<log crudo>"],
    "dstip": "-",
    "data_log": {
      "...": "...todos los campos originales de data...",
      "criticidad": "HIGH",
      "fecha": "2026-07-21",
      "modelo": "BancaDigital: Posible fuerza bruta..."
    }
  },
  "hash": "<alert_id>",
  "fuente": "transacciones"
}
```

## Extensibilidad

Para agregar una nueva fuente de log a la integración:

1. Agregar su IP/origen a `FUENTES_MAP`, o
2. Agregar una condición nueva en `determinar_fuente()` si se identifica por otro
   criterio (extensión de archivo, campo `data.integration`, etc.).

No es necesario tocar `construir_payload()` ni `enviar_alerta()`.
