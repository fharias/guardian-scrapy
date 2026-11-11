# guardian-scrapy

Proxy inverso en Go. Recibe HTTP en una dirección local y reenvía cada petición a un upstream, con timeouts, cabeceras `X-Forwarded-*`, comprobaciones de salud y apagado ordenado ante `SIGINT` o `SIGTERM`.

## Qué hay

- **`guardian`**: el proxy. Carga un YAML, valida la configuración y sirve con `httputil.ReverseProxy`.
- **`upstream`**: servidor de prueba. Responde en texto plano con la ruta, el `Host` y las cabeceras reenviadas. La ruta `/lento` espera 10 segundos antes de responder.
- **`guardian-config.yml`**: configuración de ejemplo. El upstream de prueba escucha en `:9000` y el YAML apunta a esa dirección.

```
cmd/guardian/          binario del proxy
cmd/upstream/          binario de prueba
internal/config/       carga y validación del YAML
guardian-config.yml
```

## Requisitos

- Go 1.27 o superior

## Configuración

`guardian` lee `guardian-config.yml` por defecto. Otra ruta se pasa con `-config`.

```yaml
listen: ":8080"
upstream: "http://localhost:9000"
read_header_timeout: 5s
read_timeout: 20s
write_timeout: 20s
idle_timeout: 10s
shutdown_timeout: 20s
drain_delay: 5s
preserve_host: true
```

| Campo | Obligatorio | Por defecto | Descripción |
| --- | --- | --- | --- |
| `listen` | no | `:8080` | Dirección en la que escucha el proxy |
| `upstream` | sí | — | URL completa del destino (`http://host:puerto`) |
| `read_header_timeout` | no | `5s` | Tiempo máximo para leer las cabeceras del cliente. Debe ser mayor que 0 |
| `read_timeout` | no | `10s` | Tiempo máximo para leer la petición completa |
| `write_timeout` | no | `10s` | Tiempo máximo para escribir la respuesta. No puede superar `shutdown_timeout` |
| `idle_timeout` | no | `10s` | Tiempo máximo de espera de la siguiente petición en una conexión keep-alive |
| `shutdown_timeout` | no | `10s` | Tiempo máximo del apagado para terminar las peticiones en curso |
| `drain_delay` | no | `10s` | Espera tras dejar de estar listo y antes de cerrar el servidor |
| `preserve_host` | no | `false` | Si es `true`, el `Host` que ve el upstream es el del cliente |

Campos desconocidos en el YAML hacen fallar el arranque. `upstream` tiene que ser una URL con esquema y host.

Además de los valores por defecto, la carga rechaza la configuración cuando:

- `shutdown_timeout` + `drain_delay` es mayor o igual a 30 segundos (límite de ECS).
- `write_timeout` es mayor que `shutdown_timeout`.

La variable de entorno `GUARDIAN_UPSTREAM` sustituye el valor de `upstream` del archivo.

## Salud y apagado

`GET /healthz` y `GET /readyz` responden `200` mientras el proceso está listo. El resto de rutas se reenvía al upstream.

Al recibir `SIGINT` o `SIGTERM`:

1. Ambos endpoints pasan a `503`.
2. El proceso espera `drain_delay`.
3. Cierra el servidor y deja terminar las peticiones en curso, como máximo durante `shutdown_timeout`.

Si ese cierre no termina a tiempo, el proceso registra `apagado forzado` y sale.

## Ejecutar

Valkey, en segundo plano y publicado en el puerto `6379`:

```bash
docker run -d --name valkey -p 6379:6379 valkey/valkey:8
```

En una terminal, el upstream de prueba:

```bash
go run ./cmd/upstream
```

En otra, el proxy:

```bash
go run ./cmd/guardian
# go run ./cmd/guardian -config /ruta/guardian-config.yml
```

Una petición de ejemplo:

```bash
curl -s http://localhost:8080/salud
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/healthz
```

La respuesta del proxy incluye la ruta, el `Host` y `X-Forwarded-For`, `X-Forwarded-Host` y `X-Forwarded-Proto`. Si el upstream no responde, el proxy devuelve `502` con el cuerpo `upstream no disponible`.

`/lento` sirve para ver el efecto de los timeouts: el upstream espera 10 segundos antes de escribir la respuesta.

```bash
curl -s http://localhost:8080/lento
```
