/**
 * Data passed to each scan job
 */
export interface ScanJobData {
    imageName: string;
    imageTag: string;
}

/**
 * Result returned after job completion
 */
export interface ScanJobResult {
    imageName: string;
    imageTag: string;
    vulnerabilitiesCount: number;
    scannedAt: Date;
}