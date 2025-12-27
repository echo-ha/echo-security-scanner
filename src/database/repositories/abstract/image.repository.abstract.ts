import { Image, ImageStatus } from '../../entities/image.entity';
import { ImageData, ImageWithSummary } from '../interfaces/images.interface';
import { Severity } from '../../entities/cve.entity';

/**
 * Abstract repository class for Image entity.
 */
export abstract class IImageRepository {
    /**
     * Find all images.
     */
    abstract findAll(): Promise<ImageData[]>;

    /**
     * Find an image by name and tag.
     */
    abstract findByNameAndTag(name: string, tag: string): Promise<Image | null>;

    /**
     * Find an image by name and tag with relations (imageCves, cve).
     * Optionally filter CVEs by severity.
     */
    abstract findByNameAndTagWithRelations(name: string, tag: string, severity?: Severity): Promise<Image | null>;

    /**
     * Find all images with CVE summary statistics.
     */
    abstract findAllWithSummary(): Promise<ImageWithSummary[]>;

    /**
     * Create a new image.
     */
    abstract create(image: Partial<Image>): Promise<Image>;

    /**
     * Update image status and related fields.
     */
    abstract updateStatus(name: string, tag: string, status: ImageStatus, errorMessage?: string | null): Promise<void>;
}

