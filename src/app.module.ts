import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DatabaseModule } from './database/database.module';
import { ImagesModule } from './images/images.module';
import { CvesModule } from './cves/cves.module';
import databaseConfig from './config/database.config';
import { Image } from './database/entities/image.entity';
import { Cve } from './database/entities/cve.entity';
import { ImageCve } from './database/entities/image-cve.entity';
import redisConfig from './config/redis.config';
import scannerConfig from './config/scanner.config';
import imagesConfig from './config/images.config';
import { BullModule } from '@nestjs/bullmq';
import { ScannerModule } from './scanner/scanner.module';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, redisConfig, scannerConfig, imagesConfig],
    }),

    // Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const dbConfig = configService.get('database');
        return {
          type: 'postgres',
          host: dbConfig.host,
          port: dbConfig.port,
          username: dbConfig.username,
          password: dbConfig.password,
          database: dbConfig.name,
          entities: [Image, Cve, ImageCve],
          synchronize: false,
        };
      },
      inject: [ConfigService],
    }),

    // BullMQ
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        connection: {
          host: configService.get('redis.host'),
          port: configService.get('redis.port'),
        },
      }),
    }),

    // Feature modules
    DatabaseModule,
    ImagesModule,
    CvesModule,
    ScannerModule
  ],
})
export class AppModule { }
