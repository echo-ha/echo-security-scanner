import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { Queue } from 'bullmq';
import { IScheduler } from '../../abstract/scheduler.abstract';
import { ScanJobData } from '../interfaces/scan-job.interface';

/**
 * BullMQ scheduler implementation.
 */
@Injectable()
export class BullMqScheduler extends IScheduler {
    private readonly logger = new Logger(BullMqScheduler.name);

    constructor(
        @InjectQueue('image-scan')
        private readonly scanQueue: Queue<ScanJobData>,
    ) {
        super();
    }

    async scheduleScan(imageName: string, imageTag: string, intervalMs: number): Promise<void> {
        const jobId = `scan-${imageName}:${imageTag}`;

        await this.scanQueue.add(
            'scan',
            {
                imageName,
                imageTag,
            },
            {
                jobId,
                repeat: {
                    every: intervalMs,
                },
                removeOnComplete: {
                    count: 10, // Keep last 10 completed jobs
                },
                removeOnFail: {
                    count: 50, // Keep last 50 failed jobs
                },
            },
        );

        this.logger.debug(`Scheduled repeatable scan for ${imageName}:${imageTag} (every ${intervalMs}ms)`);
    }

    async removeScheduledScan(imageName: string, imageTag: string): Promise<void> {
        const jobId = `scan-${imageName}:${imageTag}`;

        const existingJobs = await this.scanQueue.getJobSchedulers();
        const existingJob = existingJobs.find((job) => job.id === jobId);

        if (existingJob) {
            await this.scanQueue.removeJobScheduler(existingJob.key);
            this.logger.debug(`Removed existing repeatable job: ${jobId}`);
        }
    }
}

