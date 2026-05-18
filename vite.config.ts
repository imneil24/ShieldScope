import { defineConfig, type Plugin } from 'vite';
import { resolve } from 'node:path';
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

function flattenExtensionHtml(): Plugin {
  return {
    name: 'flatten-extension-html',
    closeBundle() {
      const pairs: [string, string][] = [
        [resolve(__dirname, 'dist/src/popup/popup.html'), resolve(__dirname, 'dist/popup.html')],
        [resolve(__dirname, 'dist/src/devtools/panel.html'), resolve(__dirname, 'dist/panel.html')],
        [resolve(__dirname, 'dist/src/devtools/devtools.html'), resolve(__dirname, 'dist/devtools.html')],
      ];
      for (const [from, to] of pairs) {
        if (!existsSync(from)) continue;
        let html = readFileSync(from, 'utf8');
        html = html.replaceAll('../../assets/', './assets/');
        html = html.replaceAll('../assets/', './assets/');
        html = html.replaceAll('src="/assets/', 'src="./assets/');
        html = html.replaceAll('href="/assets/', 'href="./assets/');
        html = html.replaceAll('src="/', 'src="./');
        html = html.replaceAll('href="/', 'href="./');
        writeFileSync(to, html);
      }
      const nested = resolve(__dirname, 'dist/src');
      if (existsSync(nested)) rmSync(nested, { recursive: true, force: true });
    },
  };
}

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        panel: resolve(__dirname, 'src/devtools/panel.html'),
        devtools: resolve(__dirname, 'src/devtools/devtools.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        content: resolve(__dirname, 'src/content/content-script.ts'),
        'content-start': resolve(__dirname, 'src/content/content-start.ts'),
        inject: resolve(__dirname, 'src/content/inject-main.ts'),
      },
      output: {
        format: 'es',
        entryFileNames(chunk) {
          if (['background', 'content', 'content-start', 'inject'].includes(chunk.name)) {
            return `${chunk.name}.js`;
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames(info) {
          if (info.names?.some((n) => n.endsWith('.html'))) {
            return '[name][extname]';
          }
          return 'assets/[name]-[hash][extname]';
        },
      },
    },
  },
  plugins: [
    flattenExtensionHtml(),
    {
      name: 'copy-manifest-and-data',
      closeBundle() {
        mkdirSync('dist', { recursive: true });
        copyFileSync(
          resolve(__dirname, 'public/manifest.json'),
          resolve(__dirname, 'dist/manifest.json'),
        );
        cpSync(
          resolve(__dirname, 'public/icons'),
          resolve(__dirname, 'dist/icons'),
          { recursive: true },
        );
        const dataDir = resolve(__dirname, 'dist/data');
        if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
        copyFileSync(
          resolve(__dirname, 'src/data/vulnerabilities.json'),
          resolve(__dirname, 'dist/data/vulnerabilities.json'),
        );
      },
    },
  ],
});
