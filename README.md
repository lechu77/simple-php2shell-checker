# simple-php2shell-checker

> Herramienta de auditoría pasiva black-box en lote para evaluar hasta 10 URLs frente a **PHP2Shell** (CVE-2026-109618 y CVE-2026-109619). Desplegada como aplicación de página única (SPA) estática en **Cloudflare Pages** con un backend serverless en **Cloudflare Pages Functions** (`/functions/api/check.js`).

---

## Características Principales

- **Frontend UI Sysadmin / CLI Theme**:
  - Estética terminal dark mode de alta densidad informativa, sin distracciones.
  - Textarea con contador en tiempo real (hasta 10 URLs por lote).
  - Botón de acción rápida `Cargar Ejemplos` y atajo de teclado `Ctrl + Enter` / `Cmd + Enter`.
  - Botón *Iniciar Auditoría* con indicador spinner de carga reactivo.
  - Tabla de resultados con estados diferenciados por color, visualización de versión PHP, detección de perímetros WAF, código HTTP y latencia.
  - Exportación de telemetría completa a archivo CSV (RFC 4180).
  - Filtrado interactivo en cliente por estado y término de búsqueda.

- **Backend en Cloudflare Pages Function (`/functions/api/check.js`)**:
  - Concurrencia controlada mediante un pool asíncrono con límite de 4 peticiones simultáneas para prevenir límites de subrequests edge y timeouts.
  - Fetch de baja sobrecarga: peticiones `HEAD` con fallback automático a `GET` (con cancelación inmediata del stream de lectura para ahorrar ancho de banda).
  - Manejo manual de redirecciones HTTP (`redirect: 'manual'`) para capturar cabeceras emitidas en saltos intermedios.
  - Timeout estricto de 4.0 segundos por objetivo con `AbortSignal`.
  - Análisis heurístico de cabeceras:
    - `X-Powered-By` y `Server` para identificar ramas fijadas:
      - **8.5**: Parcheado en &ge; 8.5.12
      - **8.4**: Parcheado en &ge; 8.4.27
      - **8.3**: Parcheado en &ge; 8.3.36
      - **8.2**: Parcheado en &ge; 8.2.35
      - **&lt; 8.2 (EOL)**: Sin parches oficiales (Vulnerable)
    - Detección de perímetros WAF (`cf-ray`, `server: cloudflare`, `x-amz-cf-id`, `x-sucuri-id`, `x-iinfo`, Akamai, Fastly, Varnish, F5).
    - Detección de cookies de sesión (`PHPSESSID`, `laravel_session`, `CAKEPHP`, `ci_session`, `symfony`, etc.) para catalogar instancias con `expose_php = Off` como **Opaque**.

---

## Estructura del Proyecto

```text
simple-php2shell-checker/
├── functions/
│   └── api/
│       ├── check.js         # Endpoint Pages Function (POST /api/check)
│       └── checker.js       # Motor modular de fingerprinting y lógica heurística
├── public/
│   ├── index.html           # SPA Sysadmin Terminal (Tailwind CSS)
│   ├── app.js               # Lógica Vanilla JavaScript (API, filtros, CSV)
│   └── style.css            # Estilos de consola y microinteracciones
├── test/
│   ├── checker.test.js      # Suite de pruebas unitarias de fingerprinting
│   └── check_endpoint.test.js # Pruebas del endpoint Pages Function
├── wrangler.toml            # Configuración para Cloudflare Pages
└── package.json             # Scripts de pruebas y utilidades
```

---

## Verificación y Tests Automatizados

Ejecutar la suite de pruebas nativa sin dependencias pesadas:

```bash
npm test
```

---

## Despliegue en Cloudflare Pages

### Opción 1: Git Integration (Recomendado)
1. Conecta este repositorio en el panel de Cloudflare Dashboard -> **Workers & Pages**.
2. Selecciona **Create application** -> **Pages** -> **Connect to Git**.
3. Parámetros de compilación:
   - **Framework preset**: None
   - **Build command**: (dejar en blanco)
   - **Build output directory**: `public`
4. Cloudflare detectará automáticamente la carpeta `/functions/` e instanciará las Pages Functions sin configuración adicional.

### Opción 2: Wrangler CLI
```bash
npx wrangler pages deploy public
```
