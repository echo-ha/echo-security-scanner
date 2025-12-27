import { Cve, Severity } from '../../entities/cve.entity';
import { AffectedImageData, CveWithAffectedCount, VulnerabilityRecord } from '../interfaces/cves.interfaces';

/**
 * Abstract repository class for Cve entity.
 */
export abstract class ICveRepository {
    /**
     * Find all CVEs with count of affected images
     */
    abstract findAllWithAffectedCount(severity?: Severity): Promise<CveWithAffectedCount[]>;

    /**
     * Find a CVE by its CVE ID (e.g., "CVE-2024-1234").
     */
    abstract findByCveId(cveId: string): Promise<Cve | null>;

    /**
     * Find all images affected by a CVE (using internal CVE id), including image details
     */
    abstract findAffectedImages(cveInternalId: string): Promise<AffectedImageData[]>;

    /**
     * Save vulnerabilities for an image
     */
    abstract saveVulnerabilitiesForImage(imageId: string, vulnerabilities: VulnerabilityRecord[]): Promise<void>;
}
