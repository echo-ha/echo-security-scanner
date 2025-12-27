import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ImagesService } from '../images/images.service';
import { IScheduler } from './abstract/scheduler.abstract';

/**
 * Handles the business logic of scheduling scan jobs.
 */
@Injectable()
export class SchedulerHandler implements OnModuleInit {
    private readonly logger = new Logger(SchedulerHandler.name);
    private readonly scanIntervalMs: number;

    constructor(
        private readonly scheduler: IScheduler,
        private readonly configService: ConfigService,
        private readonly imagesService: ImagesService,
    ) {
        this.scanIntervalMs = this.configService.get<number>('scanner.intervalMs', 900000);
    }

    /**
     * Sets up repeatable jobs for all images when the module initializes.
     */
    async onModuleInit(): Promise<void> {
        await this.scheduleAllScans();
    }

    /**
     * Schedule repeatable scan jobs for all images in the database.
     */
    async scheduleAllScans(): Promise<void> {
        const images = await this.imagesService.findAll();

        this.logger.log(`Scheduling scans for ${images.length} images`);

        for (const image of images) {
            await this.scheduleScan(image.name, image.tag);
        }

        this.logger.log(
            `All scans scheduled. Interval: ${this.scanIntervalMs}ms (${this.scanIntervalMs / 60000} minutes)`,
        );
    }

    /**
     * Schedule a repeatable scan job for a single image.
     * Removes existing scheduled job first to avoid duplicates.
     */
    async scheduleScan(imageName: string, imageTag: string): Promise<void> {
        await this.scheduler.removeScheduledScan(imageName, imageTag);

        await this.scheduler.scheduleScan(imageName, imageTag, this.scanIntervalMs);

        this.logger.debug(`Scheduled repeatable scan for ${imageName}:${imageTag}`);
    }
}

