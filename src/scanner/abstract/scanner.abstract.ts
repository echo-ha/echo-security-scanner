import { VulnerabilityRecord } from '../../database/repositories/interfaces/cves.interfaces';

/**
 * Abstract scanner interface.
 */
export abstract class IScanner {
    /**
     * Scan a container image and return vulnerability records.
     * @param imageName - The container image name
     * @param imageTag - The container image tag
     * @returns Array of vulnerability records
     */
    abstract scan(imageName: string, imageTag: string): Promise<VulnerabilityRecord[]>;
}
