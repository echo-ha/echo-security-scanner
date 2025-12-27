import { Severity } from "../database/entities/cve.entity";

export interface CveInfo {
    cveId: string;
    severity: Severity;
    title: string | null;
}

export interface AffectedImageInfo {
    name: string;
    tag: string;
    packageName: string;
    installedVersion: string | null;
    fixedVersion: string | null;
}

/**
 * CVE with all affected images and their package details.
 */
export interface CveWithAffectedImages {
    cve: CveInfo;
    affectedImages: AffectedImageInfo[];
}