import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Image, ImageStatus } from '../entities/image.entity';
import { IImageRepository } from './abstract/image.repository.abstract';
import { ImageWithSummary, ImageData } from './interfaces/images.interface';
import { Severity } from '../entities/cve.entity';

@Injectable()
export class ImageRepository extends IImageRepository {
    constructor(
        @InjectRepository(Image)
        private readonly repository: Repository<Image>,
    ) {
        super();
    }

    async findAll(): Promise<ImageData[]> {
        const images = await this.repository.find(
            { select: ['name', 'tag'] }
        );

        return images.map((img) => ({ name: img.name, tag: img.tag }));
    }

    async findByNameAndTag(name: string, tag: string): Promise<Image | null> {
        return this.repository.findOne({
            where: { name, tag },
        });
    }

    async findByNameAndTagWithRelations(name: string, tag: string, severity?: Severity): Promise<Image | null> {
        const queryBuilder = this.repository
            .createQueryBuilder('image')
            .leftJoinAndSelect('image.imageCves', 'imageCve')
            .leftJoinAndSelect('imageCve.cve', 'cve')
            .where('image.name = :name', { name })
            .andWhere('image.tag = :tag', { tag });

        if (severity) {
            queryBuilder.andWhere('cve.severity = :severity', { severity });
        }

        return queryBuilder.getOne();
    }

    async findAllWithSummary(): Promise<ImageWithSummary[]> {
        const results = await this.repository
            .createQueryBuilder('image')
            .leftJoin('image.imageCves', 'imageCve')
            .leftJoin('imageCve.cve', 'cve')
            .select([
                'image.id AS id',
                'image.name AS name',
                'image.tag AS tag',
                'image.status AS status',
                'image.lastScannedAt AS "lastScannedAt"',
                `COUNT(CASE WHEN cve.severity = '${Severity.CRITICAL}' THEN 1 END) AS critical`,
                `COUNT(CASE WHEN cve.severity = '${Severity.HIGH}' THEN 1 END) AS high`,
                `COUNT(CASE WHEN cve.severity = '${Severity.MEDIUM}' THEN 1 END) AS medium`,
                `COUNT(CASE WHEN cve.severity = '${Severity.LOW}' THEN 1 END) AS low`,
                'COUNT(cve.id) AS total',
            ])
            .groupBy('image.id')
            .getRawMany();

        return results.map((row) => ({
            id: row.id,
            name: row.name,
            tag: row.tag,
            status: row.status,
            lastScannedAt: row.lastScannedAt,
            cveSummary: {
                critical: parseInt(row.critical) || 0,
                high: parseInt(row.high) || 0,
                medium: parseInt(row.medium) || 0,
                low: parseInt(row.low) || 0,
                total: parseInt(row.total) || 0,
            },
        }));
    }

    async create(image: Partial<Image>): Promise<Image> {
        return this.repository.save(image);
    }

    async updateStatus(name: string, tag: string, status: ImageStatus, errorMessage?: string | null): Promise<void> {
        const updateData: Partial<Image> = {
            status,
            errorMessage: errorMessage || null,
        };

        if (status === ImageStatus.COMPLETED) {
            updateData.lastScannedAt = new Date();
        }

        await this.repository.update({ name, tag }, updateData);
    }
}

