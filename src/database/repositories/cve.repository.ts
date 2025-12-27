import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DataSource, Repository } from 'typeorm';
import { Cve, Severity } from '../entities/cve.entity';
import { ICveRepository } from './abstract/cve.repository.abstract';
import { ImageCve } from '../entities/image-cve.entity';
import { AffectedImageData, CveWithAffectedCount, VulnerabilityRecord } from './interfaces/cves.interfaces';

@Injectable()
export class CveRepository extends ICveRepository {
    constructor(
        @InjectRepository(Cve)
        private readonly cveRepo: Repository<Cve>,
        @InjectRepository(ImageCve)
        private readonly imageCveRepo: Repository<ImageCve>,
        private readonly dataSource: DataSource,
    ) {
        super();
    }

    async findAllWithAffectedCount(severity?: Severity): Promise<CveWithAffectedCount[]> {
        const queryBuilder = this.cveRepo
            .createQueryBuilder('cve')
            .leftJoin('cve.imageCves', 'imageCve')
            .select([
                'cve.id AS id',
                'cve.cveId AS "cveId"',
                'cve.severity AS severity',
                'cve.title AS title',
                'COUNT(DISTINCT imageCve.imageId) AS "affectedImagesCount"',
            ])
            .groupBy('cve.id');

        if (severity) {
            queryBuilder.where('cve.severity = :severity', { severity });
        }

        const results = await queryBuilder.getRawMany();

        return results.map((row) => ({
            id: row.id,
            cveId: row.cveId,
            severity: row.severity,
            title: row.title,
            affectedImagesCount: parseInt(row.affectedImagesCount, 10) || 0,
        }));
    }

    async findByCveId(cveId: string): Promise<Cve | null> {
        return this.cveRepo.findOne({ where: { cveId } });
    }

    async findAffectedImages(cveInternalId: string): Promise<AffectedImageData[]> {
        const imageCves: ImageCve[] = await this.imageCveRepo.find({
            where: { cveId: cveInternalId },
            relations: ['image'],
        });

        return imageCves.map((ic) => ({
            packageName: ic.packageName,
            installedVersion: ic.installedVersion,
            fixedVersion: ic.fixedVersion,
            image: {
                name: ic.image.name,
                tag: ic.image.tag,
            },
        }));
    }

    async saveVulnerabilitiesForImage(
        imageId: string,
        vulnerabilities: VulnerabilityRecord[],
    ): Promise<void> {
        await this.dataSource.transaction(async (manager) => {
            // Delete existing ImageCve records for this image
            await manager.delete(ImageCve, { imageId });

            for (const vuln of vulnerabilities) {
                let cve = await manager.findOne(Cve, {
                    where: { cveId: vuln.cve.cveId },
                });

                if (!cve) {
                    cve = manager.create(Cve, vuln.cve);
                    cve = await manager.save(cve);
                }

                const imageCve = manager.create(ImageCve, {
                    imageId,
                    cveId: cve.id,
                    packageName: vuln.imageCve.packageName,
                    installedVersion: vuln.imageCve.installedVersion,
                    fixedVersion: vuln.imageCve.fixedVersion,
                });

                await manager.save(imageCve);
            }
        });
    }
}
