import { Severity } from '../../entities/cve.entity';

/**
 * CVE with count of affected images
 */
export interface CveWithAffectedCount {
    id: string;
    cveId: string;
    severity: Severity;
    title: string | null;
    affectedImagesCount: number;
}

/**
 * Image affected by a CVE (with package details)
 */
export interface AffectedImageData {
    packageName: string;
    installedVersion: string | null;
    fixedVersion: string | null;
    image: {
        name: string;
        tag: string;
    };
}

/**
 * Data needed to create a CVE record
 */
export interface CreateCveData {
    cveId: string;
    severity: Severity;
    title: string | null;
}

/**
 * Data needed to create an ImageCve record
 */
export interface CreateImageCveData {
    packageName: string;
    installedVersion: string | null;
    fixedVersion: string | null;
}

/**
 * Combined vulnerability data for saving scan results
 */
export interface VulnerabilityRecord {
    cve: CreateCveData;
    imageCve: CreateImageCveData;
}