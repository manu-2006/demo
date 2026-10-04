import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'

export default defineConfig({
  plugins: [
    {
      name: 'spa-route-fallbacks',
      closeBundle() {
        const dist = path.resolve('dist')
        for (const route of ['admin', 'kitchen']) {
          const dir = path.join(dist, route)
          fs.mkdirSync(dir, { recursive: true })
          fs.copyFileSync(path.join(dist, 'index.html'), path.join(dir, 'index.html'))
        }
      }
    }
  ]
})
