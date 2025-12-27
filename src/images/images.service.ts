import { Injectable, Logger, NotFoundException, OnModuleInit } from "@nestjs/common";
import { Image, ImageStatus } from "../database/entities/image.entity";
import { ConfigService } from "@nestjs/config";
import { ImageConfig } from '../config/images.config';
import { ImageData, ImageWithSummary } from '../database/repositories/interfaces/images.interface';
import { IImageRepository } from '../database/repositories/abstract/image.repository.abstract';
import { Severity } from "../database/entities/cve.entity";
import { ImageCveDto, ImageWithCvesDto } from "./dto/image-response.dto";


@Injectable()
export class ImagesService implements OnModuleInit {
    private readonly logger = new Logger(ImagesService.name);

    constructor(
        private readonly imageRepository: IImageRepository,
        private readonly configService: ConfigService,
    ) { }

    /**
     * Seeds the configured images into the database.
     */
    async onModuleInit(): Promise<void> {
        await this.seedImages();
    }

    /**
     * Seeds images from config into the database.
     * Only creates images that don't already exist.
     */
    private async seedImages(): Promise<void> {
        const images = this.configService.get<ImageConfig[]>('images') || [];

        for (const image of images) {
            const existing = await this.imageRepository.findByNameAndTag(image.name, image.tag);

            if (!existing) {
                await this.createImage(image.name, image.tag);
                this.logger.log(`Image seeded: ${image.name}:${image.tag}`);
            }
        }
    }

    /**
     * Get all images from db
     */
    async findAll(): Promise<ImageData[]> {
        return this.imageRepository.findAll();
    }

    /**
     * Get all images with CVE summary statistics.
     */
    async findAllWithSummary(): Promise<ImageWithSummary[]> {
        return this.imageRepository.findAllWithSummary();
    }

    /**
     * Get image with all its CVEs.
     */
    async findByNameAndTagWithCves(
        name: string,
        tag: string,
        severity?: Severity,
    ): Promise<ImageWithCvesDto> {
        const image = await this.imageRepository.findByNameAndTagWithRelations(name, tag, severity);

        if (!image) {
            throw new NotFoundException(`Image not found: ${name}:${tag}`);
        }

        const cves: ImageCveDto[] = image.imageCves.map((imageCve) => ({
            cveId: imageCve.cve.cveId,
            severity: imageCve.cve.severity,
            title: imageCve.cve.title,
            packageName: imageCve.packageName,
            installedVersion: imageCve.installedVersion,
            fixedVersion: imageCve.fixedVersion,
        }));

        return {
            id: image.id,
            name: image.name,
            tag: image.tag,
            status: image.status,
            lastScannedAt: image.lastScannedAt,
            cves,
        };
    }

    /**
     * Find a single image by name and tag, including its CVEs.
     */
    async findByNameAndTag(name: string, tag: string): Promise<Image> {
        const image = await this.imageRepository.findByNameAndTagWithRelations(name, tag);

        if (!image) {
            throw new NotFoundException(`Image not found ${name}:${tag}`);
        }

        return image;
    }

    /**
     * Update image scan status.
     */
    async updateStatus(name: string, tag: string, status: ImageStatus, errorMessage?: string): Promise<void> {
        const existing = await this.imageRepository.findByNameAndTag(name, tag);
        if (!existing) {
            throw new NotFoundException(`Image not found ${name}:${tag}`);
        }

        await this.imageRepository.updateStatus(name, tag, status, errorMessage);
        this.logger.log(`Updated image ${name}:${tag} status to ${status}`);
    }

    /**
     * Find image by name and tag, or create if not exists.
     */
    async findOrCreate(name: string, tag: string): Promise<Image> {
        let image = await this.imageRepository.findByNameAndTag(name, tag);

        if (!image) {
            image = await this.createImage(name, tag);
            this.logger.log(`Created image: ${name}:${tag}`);
        }

        return image;
    }

    /**
     * Creates a new image with PENDING status.
     */
    private async createImage(name: string, tag: string): Promise<Image> {
        return await this.imageRepository.create({
            name,
            tag,
            status: ImageStatus.PENDING,
        });
    }
}