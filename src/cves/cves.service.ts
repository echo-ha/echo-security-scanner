import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ICveRepository } from "../database/repositories/abstract/cve.repository.abstract";
import { IImageRepository } from "../database/repositories/abstract/image.repository.abstract";
import { AffectedImageData, VulnerabilityRecord } from "../database/repositories/interfaces/cves.interfaces";
import { Severity } from "../database/entities/cve.entity";
import { CveWithAffectedCountDto, CveWithImagesDto } from './dto/cve-response.dto';

@Injectable()
export class CvesService {
    private readonly logger = new Logger(CvesService.name);

    constructor(
        private readonly cvesRepository: ICveRepository,
        private readonly imagesRepository: IImageRepository,
    ) { }

    /**
     * Get all CVEs with count of affected images.
     */
    async findAllWithAffectedCount(severity?: Severity): Promise<CveWithAffectedCountDto[]> {
        const cves = await this.cvesRepository.findAllWithAffectedCount(severity);
        return cves.map((cve) => ({
            id: cve.id,
            cveId: cve.cveId,
            severity: cve.severity,
            title: cve.title,
            affectedImagesCount: cve.affectedImagesCount,
        }));
    }

    /**
     * Get all images affected by a specific CVE.
     */
    async findImagesByCveId(cveId: string): Promise<CveWithImagesDto> {
        const cve = await this.cvesRepository.findByCveId(cveId);

        if (!cve) {
            throw new NotFoundException(`CVE not found: ${cveId}`);
        }

        const affectedImages: AffectedImageData[] = await this.cvesRepository.findAffectedImages(cve.id);

        return {
            cve: {
                cveId: cve.cveId,
                severity: cve.severity,
                title: cve.title,
            },
            affectedImages: affectedImages.map((img) => ({
                name: img.image.name,
                tag: img.image.tag,
                packageName: img.packageName,
                installedVersion: img.installedVersion,
                fixedVersion: img.fixedVersion,
            })),
        };
    }

    /**
     * Save vulnerabilities from a scan.
     */
    async saveVulnerabilities(
        imageName: string,
        imageTag: string,
        vulnerabilities: VulnerabilityRecord[],
    ): Promise<void> {
        const image = await this.imagesRepository.findByNameAndTag(imageName, imageTag);

        if (!image) {
            throw new NotFoundException(`Image not found: ${imageName}:${imageTag}`);
        }

        await this.cvesRepository.saveVulnerabilitiesForImage(image.id, vulnerabilities);

        this.logger.log(
            `Saved ${vulnerabilities.length} vulnerabilities for ${imageName}:${imageTag}`,
        );
    }
}