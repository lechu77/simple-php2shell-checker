# Guía de Despliegue en Cloudflare Pages

Esta guía detalla los métodos disponibles para desplegar **simple-php2shell-checker** en Cloudflare Pages manteniendo operativas las funciones edge (`/functions/api/check.js`).

---

## Requisitos Previos

- Cuenta gratuita o de pago en [Cloudflare](https://dash.cloudflare.com/).
- Repositorio en GitHub/GitLab (para despliegue continuo) o [Node.js](https://nodejs.org/) v18+ instalado (para despliegue vía CLI).

---

## Método 1: Despliegue Automático vía Git (Recomendado)

Cada vez que hagas `git push` a tu rama principal (`main`), Cloudflare compilará y desplegará tu aplicación automáticamente.

1. **Accede al panel de Cloudflare**:
   - Entra en [Cloudflare Dashboard](https://dash.cloudflare.com/).
   - En el menú lateral izquierdo, ve a **Workers & Pages** -> **Overview**.
   - Haz clic en **Create application** y selecciona la pestaña **Pages**.
   - Haz clic en **Connect to Git**.

2. **Selecciona tu repositorio**:
   - Conecta tu cuenta de GitHub/GitLab y busca el repositorio `simple-php2shell-checker`.
   - Haz clic en **Begin setup**.

3. **Configuración de compilación (Build Settings)**:
   - **Project name**: `simple-php2shell-checker` (o el nombre que desees).
   - **Production branch**: `main`.
   - **Framework preset**: `None` (no se requiere framework ni build step).
   - **Build command**: *(dejar completamente vacío)*.
   - **Build output directory**: `public`.
   - **Root directory**: *(dejar vacío o `/`)*.

4. **Variables de entorno y compatibilidad**:
   - No se requieren variables de entorno obligatorias para el modo básico.
   - Cloudflare Pages detectará automáticamente la carpeta `/functions/` en la raíz del proyecto y creará la ruta `/api/check`.

5. **Guardar y desplegar**:
   - Haz clic en **Save and Deploy**.
   - En aproximadamente 30-45 segundos tendrás tu URL pública activa (ej. `https://simple-php2shell-checker.pages.dev`).

---

## Método 2: Despliegue Directo vía Wrangler CLI

Si prefieres desplegar directamente desde tu terminal sin vincular Git a Cloudflare:

1. **Iniciar sesión en Cloudflare**:
   ```bash
   npx wrangler login
   ```
   *Se abrirá una ventana de navegador para autorizar a Wrangler en tu cuenta de Cloudflare.*

2. **Desplegar el proyecto**:
   ```bash
   npm run deploy
   ```
   O directamente:
   ```bash
   npx wrangler pages deploy public --project-name=simple-php2shell-checker
   ```

3. **Seleccionar entorno**:
   - Wrangler te preguntará si deseas crear el proyecto nuevo (si es la primera vez) y si es para `Production` o `Preview`.
   - Al finalizar, devolverá la URL asignada.

---

## Método 3: Despliegue Automatizado con GitHub Actions

Para desplegar automáticamente en cada commit mediante GitHub Actions:

Crea el archivo `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Cloudflare Pages

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      deployments: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Run Test Suite
        run: npm test

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: pages deploy public --project-name=simple-php2shell-checker
```

*(Configura los secrets `CLOUDFLARE_API_TOKEN` y `CLOUDFLARE_ACCOUNT_ID` en **Settings -> Secrets and variables -> Actions** en tu repositorio de GitHub).*

---

## Verificación y Pruebas Locales antes de Desplegar

Puedes ejecutar y depurar localmente la aplicación estática junto con las Pages Functions:

1. **Lanzar el entorno de desarrollo local de Cloudflare**:
   ```bash
   npm run dev
   ```
   Esto levantará el servidor en `http://localhost:8788`.

2. **Probar el endpoint de la API con cURL**:
   ```bash
   curl -s -X POST http://localhost:8788/api/check \
     -H "Content-Type: application/json" \
     -d '{"urls": ["https://www.php.net"]}' | jq .
   ```

3. **Ejecutar la suite de tests unitarios**:
   ```bash
   npm test
   ```

---

## Resolución de Problemas (Troubleshooting)

- **Error 404 al llamar a `/api/check`**:
  - Asegúrate de que el **Build output directory** esté configurado como `public` y que la carpeta `functions/` esté situada en la raíz del repositorio (`functions/api/check.js`).
- **Límite de subrequests en Cloudflare Workers**:
  - El plan gratuito de Cloudflare Pages Functions permite hasta 50 subrequests por invocación. El auditor procesa un máximo de 10 URLs con un pool de concurrencia de 4 para operar siempre dentro de los límites seguros.
- **Error CORS**:
  - `functions/api/check.js` incluye cabeceras `Access-Control-Allow-Origin: *` y soporte para peticiones `OPTIONS`, lo que permite probar la API tanto en el mismo dominio como desde clientes externos.
