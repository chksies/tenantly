import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { migrate } from '../src/scripts/migrate.js';
import { adminUrl } from './env.js';

export default async function setup() {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(await readFile('db/init/01-roles.sql', 'utf8'));
    await client.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT USAGE ON SCHEMA public TO PUBLIC;');
  } finally {
    await client.end();
  }
  await migrate(adminUrl);
}
