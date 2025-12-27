import { Controller, Get, Param, Query } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ImagesService } from "./images.service";
import { ImageWithSummaryDto, ImageWithCvesDto } from './dto/image-response.dto';
import { Severity } from '../database/entities/cve.entity';
import { ApiGetAllImages, ApiGetImageCves } from '../common/decorators/api-docs.decorator';

@ApiTags('images')
@Controller('images')
export class ImagesController {
    constructor(private readonly imagesService: ImagesService) { }

    /**
     * GET /api/images
     * Returns all images with CVE summary statistics
     */
    @Get()
    @ApiGetAllImages()
    async findAll(): Promise<ImageWithSummaryDto[]> {
        return this.imagesService.findAllWithSummary();
    }

    /**
     * GET /api/images/:name/:tag/cves
     * Returns a specific image with all its CVEs
     * Optionally filter by severity
     */
    @Get(':name/:tag/cves')
    @ApiGetImageCves()
    async findImageCves(
        @Param('name') name: string,
        @Param('tag') tag: string,
        @Query('severity') severity?: Severity,
    ): Promise<ImageWithCvesDto> {
        return this.imagesService.findByNameAndTagWithCves(name, tag, severity);
    }
}