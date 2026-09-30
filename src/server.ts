import { buildApp } from './app.js';
import { config } from './config.js';
import { closePools } from './db.js';

const app = await buildApp();

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, async () => {
    app.log.info({ signal }, 'shutting down');
    await app.close();
    await closePools();
    process.exit(0);
  });
}

await app.listen({ port: config.PORT, host: '0.0.0.0' });
