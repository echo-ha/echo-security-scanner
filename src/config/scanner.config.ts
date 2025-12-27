import { registerAs } from '@nestjs/config';

export default registerAs('scanner', () => ({
    intervalMs: process.env.SCAN_INTERVAL_MS
        ? parseInt(process.env.SCAN_INTERVAL_MS, 10)
        : 15 * 60 * 1000,
    timeoutMs: process.env.SCAN_TIMEOUT_MS
        ? parseInt(process.env.SCAN_TIMEOUT_MS, 10)
        : 5 * 60 * 1000,
    workerConcurrency: process.env.WORKER_CONCURRENCY
        ? parseInt(process.env.WORKER_CONCURRENCY, 10)
        : 3,
}));