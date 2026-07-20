// backend/src/app.ts
import express from 'express';
import { authRouter } from './modules/auth/auth.controller.js';

const app = express();
app.use(express.json());

// Bind modular routers
app.use('/api/auth', authRouter);

export default app;