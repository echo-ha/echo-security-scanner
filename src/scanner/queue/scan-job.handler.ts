import { Injectable, Logger } from '@nestjs/common';
import { ScannerService } from '../scanner.service';
import { ImagesService } from '../../images/images.service';
import { CvesService } from '../../cves/cves.service';
import { ImageStatus } from '../../database/entities/image.entity';
import { ScanJobData, ScanJobResult } from './interfaces/scan-job.interface';

/**
 * Handles the business logic of processing scan jobs.
 */
@Injectable()
export class ScanJobHandler {
    private readonly logger = new Logger(ScanJobHandler.name);

    constructor(
        private readonly scannerService: ScannerService,
        private readonly cvesService: CvesService,
        private readonly imagesService: ImagesService,
    ) { }

    /**
     * Process a scan job with the given data.
     * This method contains the core business logic and is independent of the queue technology.
     */
    async process(jobData: ScanJobData, jobId?: string): Promise<ScanJobResult> {
        const { imageName, imageTag } = jobData;
        const fullImage = `${imageName}:${imageTag}`;

        this.logger.log(`Processing scan job for ${fullImage}${jobId ? ` (Job ID: ${jobId})` : ''}`);

        try {
            await this.imagesService.updateStatus(imageName, imageTag, ImageStatus.SCANNING);

            const vulnerabilities = await this.scannerService.scan(imageName, imageTag);

            await this.cvesService.saveVulnerabilities(imageName, imageTag, vulnerabilities);

            await this.imagesService.updateStatus(imageName, imageTag, ImageStatus.COMPLETED);

            this.logger.log(
                `Scan completed for ${fullImage}: ${vulnerabilities.length} vulnerabilities found`,
            );

            return {
                imageName,
                imageTag,
                vulnerabilitiesCount: vulnerabilities.length,
                scannedAt: new Date(),
            };

        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';

            await this.imagesService.updateStatus(imageName, imageTag, ImageStatus.FAILED, errorMessage);

            this.logger.error(`Scan failed for ${fullImage}: ${errorMessage}`);

            throw error;
        }
    }

    /**
     * Called when a job completes successfully.
     */
    onCompleted(jobData: ScanJobData, result: ScanJobResult, jobId?: string): void {
        this.logger.debug(
            `Job ${jobId || 'unknown'} completed for ${result.imageName}:${result.imageTag}`,
        );
    }

    /**
     * Called when a job fails.
     */
    onFailed(jobData: ScanJobData, error: Error, jobId?: string): void {
        this.logger.error(
            `Job ${jobId || 'unknown'} failed for ${jobData.imageName}:${jobData.imageTag}: ${error.message}`,
        );
    }
}

