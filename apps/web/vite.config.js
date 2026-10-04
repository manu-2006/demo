import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [
    {
      name: 'spa-route-fallbacks',
      generateBundle(_options, bundle) {
        const index = bundle['index.html']
        if (!index || index.type !== 'asset') return
        for (const route of ['admin', 'kitchen', 'platform', 't']) {
          this.emitFile({
            type: 'asset',
            fileName: route + '/index.html',
            source: index.source
          })
        }
      }
    }
  ]
})
