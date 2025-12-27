import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { exec } from 'child_process';
import { promisify } from 'util';
import { IScanner } from '../../abstract/scanner.abstract';
import { VulnerabilityRecord } from '../../../database/repositories/interfaces/cves.interfaces';
import { Severity } from '../../../database/entities/cve.entity';
import { TrivyVulnerability, TrivyOutput } from './trivy.interface';

const execAsync = promisify(exec);

/**
 * Trivy scanner implementation.
 */
@Injectable()
export class TrivyScanner extends IScanner {
    private readonly logger = new Logger(TrivyScanner.name);
    private readonly timeoutMs: number;

    constructor(private readonly configService: ConfigService) {
        super();
        this.timeoutMs = this.configService.get<number>('scanner.timeoutMs', 300000);
    }

    async scan(imageName: string, imageTag: string): Promise<VulnerabilityRecord[]> {
        const fullImage = `${imageName}:${imageTag}`;
        this.logger.debug(`Executing Trivy scan for ${fullImage}`);

        const jsonOutput = await this.executeTrivyScan(fullImage);
        const vulnerabilities = this.parseResults(jsonOutput);

        this.logger.debug(`Trivy scan completed for ${fullImage}. Found ${vulnerabilities.length} vulnerabilities.`);

        return vulnerabilities;
    }

    /**
     * Execute Trivy CLI command and return raw JSON output.
     */
    private async executeTrivyScan(fullImage: string): Promise<string> {
        const command = `trivy image --format json --quiet ${fullImage}`;

        this.logger.debug(`Executing Trivy command: ${command}`);

        try {
            const { stdout, stderr } = await execAsync(command, {
                timeout: this.timeoutMs,
                maxBuffer: 50 * 1024 * 1024, // 50MB
            });

            if (stderr && !stderr.includes('Downloading')) {
                this.logger.warn(`Trivy stderr: ${stderr}`);
            }

            return stdout;
        } catch (error) {
            if (error.killed) {
                throw new Error(`Trivy scan timed out after ${this.timeoutMs}ms for image: ${fullImage}`);
            }

            if (error.stderr?.includes('UNAUTHORIZED') || error.stderr?.includes('not found')) {
                throw new Error(`Image ${fullImage} not found or unauthorized`);
            }

            throw new Error(`Trivy scan failed: ${error.message} for image: ${fullImage}`);
        }
    }

    /**
     * Parse Trivy JSON output into VulnerabilityRecord array.
     */
    private parseResults(jsonOutput: string): VulnerabilityRecord[] {
        const trivyOutput = this.parseJsonOutput(jsonOutput);

        if (!trivyOutput.Results?.length) {
            this.logger.debug('No results in Trivy output');
            return [];
        }

        const vulnerabilities = trivyOutput.Results.flatMap(result => result.Vulnerabilities || []);
        return this.mapAndDeduplicateVulnerabilities(vulnerabilities);
    }

    /**
     * Parse JSON string into TrivyOutput object.
     */
    private parseJsonOutput(jsonOutput: string): TrivyOutput {
        try {
            return JSON.parse(jsonOutput);
        } catch (error) {
            this.logger.error('Failed to parse Trivy JSON output', error);
            throw new Error('Invalid Trivy JSON output');
        }
    }

    /**
     * Map Trivy vulnerabilities to VulnerabilityRecord and deduplicate by CVE ID + package name.
     */
    private mapAndDeduplicateVulnerabilities(
        vulnerabilities: TrivyVulnerability[],
    ): VulnerabilityRecord[] {
        const seen = new Map<string, VulnerabilityRecord>();

        for (const vuln of vulnerabilities) {
            const mapped = this.mapVulnerability(vuln);
            const key = `${mapped.cve.cveId}:${mapped.imageCve.packageName}`;

            if (!seen.has(key)) {
                seen.set(key, mapped);
            }
        }

        const deduplicated = Array.from(seen.values());

        if (deduplicated.length < vulnerabilities.length) {
            this.logger.debug(
                `Deduplicated ${vulnerabilities.length} vulnerabilities to ${deduplicated.length} unique entries`,
            );
        }

        return deduplicated;
    }

    /**
     * Map a single Trivy vulnerability to VulnerabilityRecord format.
     */
    private mapVulnerability(vuln: TrivyVulnerability): VulnerabilityRecord {
        return {
            cve: {
                cveId: vuln.VulnerabilityID,
                severity: this.mapSeverity(vuln.Severity),
                title: vuln.Title || null,
            },
            imageCve: {
                packageName: vuln.PkgName,
                installedVersion: vuln.InstalledVersion || null,
                fixedVersion: vuln.FixedVersion || null,
            },
        };
    }

    private mapSeverity(severity: string): Severity {
        const upper = severity?.toUpperCase();

        switch (upper) {
            case 'CRITICAL':
                return Severity.CRITICAL;
            case 'HIGH':
                return Severity.HIGH;
            case 'MEDIUM':
                return Severity.MEDIUM;
            case 'LOW':
                return Severity.LOW;
            default:
                return Severity.UNKNOWN;
        }
    }
}

