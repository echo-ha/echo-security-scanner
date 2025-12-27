import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import { ScannerService } from './scanner.service';
import { IScanner } from './abstract/scanner.abstract';
import { TrivyScanner } from './scanners/trivy/trivy.scanner';
import { ScanJobHandler } from './queue/scan-job.handler';
import { BullMqProcessor } from './queue/implementations/bullmq.processor';
import { SchedulerHandler } from './scheduler.handler';
import { IScheduler } from './abstract/scheduler.abstract';
import { BullMqScheduler } from './queue/implementations/bullmq.scheduler';
import { ImagesModule } from '../images/images.module';
import { CvesModule } from '../cves/cves.module';

@Module({
    imports: [
        ConfigModule,
        BullModule.registerQueue({
            name: 'image-scan',
        }),
        ImagesModule,
        CvesModule,
    ],
    providers: [
        {
            provide: IScanner,
            useClass: TrivyScanner,
        },
        {
            provide: IScheduler,
            useClass: BullMqScheduler,
        },
        ScannerService,
        ScanJobHandler,
        BullMqProcessor,
        SchedulerHandler,
        BullMqScheduler,
    ],
    exports: [ScannerService],
})
export class ScannerModule { }

