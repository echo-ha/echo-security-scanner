import { CveWithAffectedCountDto, CveWithImagesDto } from "./dto/cve-response.dto";
import { CvesService } from "./cves.service";
import { Controller, Get, Param, Query } from "@nestjs/common";
import { ApiTags } from "@nestjs/swagger";
import { Severity } from "../database/entities/cve.entity";
import { ApiGetAllCves, ApiGetCveImages } from '../common/decorators/api-docs.decorator';

@ApiTags('cves')
@Controller('api/cves')
export class CvesController {
    constructor(private readonly cvesService: CvesService) { }

    /**
     * GET /api/cves
     * Returns all CVEs with count of affected images
     * Optionally filter by severity
     */
    @Get()
    @ApiGetAllCves()
    async findAll(
        @Query('severity') severity?: Severity,
    ): Promise<CveWithAffectedCountDto[]> {
        return this.cvesService.findAllWithAffectedCount(severity);
    }

    /**
     * GET /api/cves/:cve_id/images
     * Returns all images affected by a specific CVE
     */
    @Get(':cve_id/images')
    @ApiGetCveImages()
    async findAffectedImages(
        @Param('cve_id') cveId: string,
    ): Promise<CveWithImagesDto> {
        return this.cvesService.findImagesByCveId(cveId);
    }
}