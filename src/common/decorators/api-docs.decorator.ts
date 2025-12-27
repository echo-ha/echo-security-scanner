import { applyDecorators } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { Severity } from '../../database/entities/cve.entity';
import { ImageWithSummaryDto, ImageWithCvesDto } from '../../images/dto/image-response.dto';
import { CveWithAffectedCountDto, CveWithImagesDto } from '../../cves/dto/cve-response.dto';

/**
 * Swagger documentation decorators for Images endpoints
 */
export const ApiGetAllImages = () =>
    applyDecorators(
        ApiOperation({
            summary: 'Get all images with CVE summary',
            description: 'Returns all container images with their CVE summary statistics including counts by severity level',
        }),
        ApiResponse({
            status: 200,
            description: 'List of images with CVE summaries',
            type: [ImageWithSummaryDto],
        }),
    );

export const ApiGetImageCves = () =>
    applyDecorators(
        ApiOperation({
            summary: 'Get CVEs for a specific image',
            description: 'Returns a specific container image with all its associated CVEs. Optionally filter by severity level.',
        }),
        ApiParam({
            name: 'name',
            description: 'Container image name',
            example: 'nginx',
        }),
        ApiParam({
            name: 'tag',
            description: 'Container image tag',
            example: '1.19',
        }),
        ApiQuery({
            name: 'severity',
            required: false,
            enum: Severity,
            description: 'Filter CVEs by severity level',
            example: Severity.HIGH,
        }),
        ApiResponse({
            status: 200,
            description: 'Image with its CVEs',
            type: ImageWithCvesDto,
        }),
        ApiResponse({
            status: 404,
            description: 'Image not found',
        }),
    );

/**
 * Swagger documentation decorators for CVEs endpoints
 */
export const ApiGetAllCves = () =>
    applyDecorators(
        ApiOperation({
            summary: 'Get all CVEs with affected image counts',
            description: 'Returns all CVEs with the count of affected images. Optionally filter by severity level.',
        }),
        ApiQuery({
            name: 'severity',
            required: false,
            enum: Severity,
            description: 'Filter CVEs by severity level',
            example: Severity.CRITICAL,
        }),
        ApiResponse({
            status: 200,
            description: 'List of CVEs with affected image counts',
            type: [CveWithAffectedCountDto],
        }),
    );

export const ApiGetCveImages = () =>
    applyDecorators(
        ApiOperation({
            summary: 'Get images affected by a specific CVE',
            description: 'Returns all container images that are affected by a specific CVE',
        }),
        ApiParam({
            name: 'cve_id',
            description: 'CVE identifier',
            example: 'CVE-2024-1234',
        }),
        ApiResponse({
            status: 200,
            description: 'CVE with list of affected images',
            type: CveWithImagesDto,
        }),
        ApiResponse({
            status: 404,
            description: 'CVE not found',
        }),
    );

