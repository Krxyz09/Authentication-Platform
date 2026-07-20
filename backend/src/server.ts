// backend/src/server.ts
import app from './app.js';
import dotenv from 'dotenv';
import { connectToDatabase } from './config/db.js';

dotenv.config();

const PORT = process.env.PORT || 3000;

async function startServer() {
  await connectToDatabase();

  app.listen(PORT, () => {
    console.log(`|-------------------------------------------------------|`);
    console.log(`| TALLY MULTI-LAYER AUTH SERVICE MASTER ROUTER RUNNING  |`);
    console.log(`| Local Node Listener Bind Target: http://localhost:${PORT} |`);
    console.log(`|-------------------------------------------------------|`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});