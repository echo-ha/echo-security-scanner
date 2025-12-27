import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ImageStatus } from '../../database/entities/image.entity';
import { Severity } from '../../database/entities/cve.entity';

export class CveSummaryDto {
    @ApiProperty({ description: 'Number of critical severity CVEs', example: 5 })
    critical!: number;

    @ApiProperty({ description: 'Number of high severity CVEs', example: 12 })
    high!: number;

    @ApiProperty({ description: 'Number of medium severity CVEs', example: 25 })
    medium!: number;

    @ApiProperty({ description: 'Number of low severity CVEs', example: 8 })
    low!: number;

    @ApiProperty({ description: 'Total number of CVEs', example: 50 })
    total!: number;
}

export class ImageWithSummaryDto {
    @ApiProperty({ description: 'Unique identifier for the image', example: '123e4567-e89b-12d3-a456-426614174000' })
    id!: string;

    @ApiProperty({ description: 'Container image name', example: 'nginx' })
    name!: string;

    @ApiProperty({ description: 'Container image tag', example: '1.19' })
    tag!: string;

    @ApiProperty({ description: 'Current scan status of the image', enum: ImageStatus, example: ImageStatus.COMPLETED })
    status!: ImageStatus;

    @ApiPropertyOptional({ description: 'Timestamp of the last scan', example: '2024-01-15T10:30:00Z', nullable: true })
    lastScannedAt!: Date | null;

    @ApiProperty({ description: 'Summary of CVEs by severity', type: () => CveSummaryDto })
    cveSummary!: CveSummaryDto;
}

export class ImageCveDto {
    @ApiProperty({ description: 'CVE identifier', example: 'CVE-2024-1234' })
    cveId!: string;

    @ApiProperty({ description: 'Severity level of the CVE', enum: Severity, example: Severity.HIGH })
    severity!: Severity;

    @ApiPropertyOptional({ description: 'Title of the CVE', example: 'Remote Code Execution vulnerability', nullable: true })
    title!: string | null;

    @ApiProperty({ description: 'Name of the affected package', example: 'openssl' })
    packageName!: string;

    @ApiPropertyOptional({ description: 'Currently installed version of the package', example: '1.1.1f', nullable: true })
    installedVersion!: string | null;

    @ApiPropertyOptional({ description: 'Version that fixes the vulnerability', example: '1.1.1g', nullable: true })
    fixedVersion!: string | null;
}

export class ImageWithCvesDto {
    @ApiProperty({ description: 'Unique identifier for the image', example: '123e4567-e89b-12d3-a456-426614174000' })
    id!: string;

    @ApiProperty({ description: 'Container image name', example: 'nginx' })
    name!: string;

    @ApiProperty({ description: 'Container image tag', example: '1.19' })
    tag!: string;

    @ApiProperty({ description: 'Current scan status of the image', enum: ImageStatus, example: ImageStatus.COMPLETED })
    status!: ImageStatus;

    @ApiPropertyOptional({ description: 'Timestamp of the last scan', example: '2024-01-15T10:30:00Z', nullable: true })
    lastScannedAt!: Date | null;

    @ApiProperty({ description: 'List of CVEs affecting this image', type: () => [ImageCveDto] })
    cves!: ImageCveDto[];
}