import { ImageStatus } from "../../entities/image.entity";

export interface CveSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
}

export interface ImageWithSummary {
    id: string;
    name: string;
    tag: string;
    status: ImageStatus;
    lastScannedAt: Date | null;
    cveSummary: CveSummary;
}

export interface ImageData {
    name: string;
    tag: string;
}