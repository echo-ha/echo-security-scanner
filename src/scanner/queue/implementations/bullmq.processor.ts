import { OnWorkerEvent, Processor, WorkerHost } from '@nestjs/bullmq';
import type { Job } from 'bullmq';
import type { ScanJobData, ScanJobResult } from '../interfaces/scan-job.interface';
import { ScanJobHandler } from '../scan-job.handler';

/**
 * BullMQ processor implementation.
 */
@Processor('image-scan')
export class BullMqProcessor extends WorkerHost {
    constructor(private readonly scanJobHandler: ScanJobHandler) {
        super();
    }

    /**
     * BullMqProcessor processes a job from the queue.
     */
    async process(job: Job<ScanJobData>): Promise<ScanJobResult> {
        return this.scanJobHandler.process(job.data, job.id);
    }

    /**
     * Called when a job completes successfully
     */
    @OnWorkerEvent('completed')
    onCompleted(job: Job<ScanJobData>, result: ScanJobResult): void {
        this.scanJobHandler.onCompleted(job.data, result, job.id);
    }

    /**
     * Called when a job fails
     */
    @OnWorkerEvent('failed')
    onFailed(job: Job<ScanJobData>, error: Error): void {
        this.scanJobHandler.onFailed(job.data, error, job.id);
    }
}

