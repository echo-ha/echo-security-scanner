/**
 * Abstract scheduler interface.
 */
export abstract class IScheduler {
    /**
     * Schedule a repeatable scan job for a single image.
     * @param imageName - The container image name
     * @param imageTag - The container image tag
     * @param intervalMs - Interval in milliseconds between scans
     */
    abstract scheduleScan(imageName: string, imageTag: string, intervalMs: number): Promise<void>;

    /**
     * Remove an existing scheduled scan job.
     * @param imageName - The container image name
     * @param imageTag - The container image tag
     */
    abstract removeScheduledScan(imageName: string, imageTag: string): Promise<void>;
}

