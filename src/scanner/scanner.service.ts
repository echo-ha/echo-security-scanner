import { Injectable, Logger } from '@nestjs/common';
import { VulnerabilityRecord } from '../database/repositories/interfaces/cves.interfaces';
import { IScanner } from './abstract/scanner.abstract';

@Injectable()
export class ScannerService {
    private readonly logger = new Logger(ScannerService.name);

    constructor(private readonly scanner: IScanner) { }

    /**
     * Scan a container image and return parsed vulnerabilities.
     * Delegates to the configured scanner implementation.
     */
    async scan(imageName: string, imageTag: string): Promise<VulnerabilityRecord[]> {
        const fullImage = `${imageName}:${imageTag}`;

        this.logger.log(`Starting scan for ${fullImage}`);

        const vulnerabilities = await this.scanner.scan(imageName, imageTag);

        this.logger.log(`Scan completed for ${fullImage}. Found ${vulnerabilities.length} vulnerabilities.`);

        return vulnerabilities;
    }
}