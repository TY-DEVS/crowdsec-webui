import fs from 'node:fs';
import path from 'node:path';
import type { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import type { RuntimeConfig } from '../config';
import type { CrowdsecDatabase } from '../database';
import { applyBrandingToIndexHtml, getPublicBranding, serializeBrandingForScript } from '../branding';

type HonoContext = any;

// Applies the saved theme before first paint, so a dark-mode refresh doesn't
// flash the light background while the app bundle loads. Mirrors
// readStoredMode() in client/src/lib/theme.ts: a missing or unknown value means
// "system". Runs as an inline script under the page's CSP nonce.
export const THEME_BOOTSTRAP_SCRIPT = "(function(){try{var m=localStorage.getItem('theme');var d=m==='dark'||(m!=='light'&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);}catch(e){}})();";

export interface RegisterStaticRoutesOptions {
  app: Hono;
  config: RuntimeConfig;
  database: CrowdsecDatabase;
  distRoot: string;
  staticFiles: string[];
  rootRedirectPath?: string;
}

export function registerStaticRoutes(options: RegisterStaticRoutesOptions): void {
  const { app, config, database, distRoot, staticFiles, rootRedirectPath } = options;

  app.use(`${config.basePath}/assets/*`, async (context, next) => {
    context.header('Cache-Control', 'public, max-age=31536000, immutable');
    await next();
  });

  app.use(
    `${config.basePath}/assets/*`,
    serveStatic({
      root: distRoot,
      rewriteRequestPath: (requestPath) => (config.basePath ? requestPath.replace(config.basePath, '') : requestPath),
    }),
  );

  app.get(`${config.basePath}/assets/*`, (context) => {
    context.header('Cache-Control', 'no-store, no-cache, must-revalidate');
    context.header('Pragma', 'no-cache');
    return context.text('Not Found', 404);
  });

  app.use(`${config.basePath}/world-50m.json`, async (context, next) => {
    context.header('Cache-Control', 'public, max-age=86400, stale-while-revalidate=604800');
    await next();
  });

  staticFiles.forEach((file) => {
    app.use(
      `${config.basePath}${file}`,
      serveStatic({
        root: distRoot,
        rewriteRequestPath: (requestPath) => (config.basePath ? requestPath.replace(config.basePath, '') : requestPath),
      }),
    );
  });

  app.get(`${config.basePath}/site.webmanifest`, (context) => {
    const branding = getPublicBranding(database, config.basePath);
    const customized = branding.appName !== branding.defaultAppName;
    context.header('Cache-Control', 'no-cache');
    return context.json({
      name: branding.appName,
      short_name: customized ? branding.appName : 'CrowdSec',
      icons: branding.logoUrl
        ? [{ src: branding.logoUrl, sizes: 'any' }]
        : [
          { src: `${config.basePath}/android-chrome-192x192.png`, sizes: '192x192', type: 'image/png' },
          { src: `${config.basePath}/android-chrome-512x512.png`, sizes: '512x512', type: 'image/png' },
        ],
      theme_color: '#ffffff',
      background_color: '#ffffff',
      display: 'standalone',
      start_url: config.basePath || '/',
    });
  });

  app.get(`${config.basePath}/*`, (context) => {
    try {
      const requestPath = new URL(context.req.url).pathname;
      const rootPath = config.basePath ? `${config.basePath}/` : '/';
      if (rootRedirectPath && requestPath === rootPath) {
        const redirectPath = `${config.basePath}${rootRedirectPath.startsWith('/') ? rootRedirectPath : `/${rootRedirectPath}`}`;
        return context.redirect(redirectPath);
      }

      const indexPath = path.join(distRoot, 'index.html');
      let html = fs.readFileSync(indexPath, 'utf-8');
      const safePath = config.basePath.replace(/[^a-zA-Z0-9/_-]/g, '');
      const cspNonce = String((context as HonoContext).get('cspNonce') || '');
      const branding = getPublicBranding(database, config.basePath);
      const configScript = `<script nonce="${cspNonce}">window.__BASE_PATH__="${safePath}";window.__BRANDING__=${serializeBrandingForScript(branding)};</script>`;
      const themeScript = `<script nonce="${cspNonce}">${THEME_BOOTSTRAP_SCRIPT}</script>`;
      html = applyBrandingToIndexHtml(html, branding);
      html = html.replace('</head>', () => `${configScript}\n${themeScript}\n</head>`);

      if (config.basePath) {
        html = html.replace(/href="\.\//g, `href="${config.basePath}/`);
        html = html.replace(/src="\.\//g, `src="${config.basePath}/`);
      }

      context.header('Cache-Control', 'no-store, no-cache, must-revalidate');
      context.header('Pragma', 'no-cache');
      context.header('Expires', '0');
      return context.html(html);
    } catch {
      return context.text('Not Found', 404);
    }
  });

  if (config.basePath) {
    app.get('/', (context) => context.redirect(`${config.basePath}/`));
  }
}
