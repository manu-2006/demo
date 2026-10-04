import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'

export default defineConfig({
  plugins: [
    {
      name: 'spa-route-fallbacks',
      closeBundle() {
        const dist = path.resolve('dist')
        const index = path.join(dist, 'index.html')
        for (const route of ['admin', 'kitchen']) {
          const dir = path.join(dist, route)
          fs.mkdirSync(dir, { recursive: true })
          fs.copyFileSync(index, path.join(dir, 'index.html'))
          fs.copyFileSync(index, path.join(dist, route))
        }
      }
    }
  ]
})
