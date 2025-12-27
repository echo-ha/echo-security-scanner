import { Module } from '@nestjs/common';
import { CvesService } from './cves.service';
import { CvesController } from './cves.controller';

@Module({
    imports: [],
    controllers: [CvesController],
    providers: [CvesService],
    exports: [CvesService],
})
export class CvesModule { }

