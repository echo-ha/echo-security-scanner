import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Image } from './entities/image.entity';
import { Cve } from './entities/cve.entity';
import { ImageCve } from './entities/image-cve.entity';
import { ImageRepository } from './repositories/image.repository';
import { CveRepository } from './repositories/cve.repository';
import { IImageRepository } from './repositories/abstract/image.repository.abstract';
import { ICveRepository } from './repositories/abstract/cve.repository.abstract';

@Global()
@Module({
    imports: [
        TypeOrmModule.forFeature([Image, Cve, ImageCve]),
    ],
    providers: [
        {
            provide: IImageRepository,
            useClass: ImageRepository,
        },
        {
            provide: ICveRepository,
            useClass: CveRepository,
        }
    ],
    exports: [
        IImageRepository,
        ICveRepository,
        TypeOrmModule,
    ],
})
export class DatabaseModule { }

