import { DocumentBuilder } from '@nestjs/swagger';

export const swaggerConfig = new DocumentBuilder()
    .setTitle('Container Security Scanner API')
    .setDescription('API for scanning container images and managing CVEs')
    .setVersion('1.0')
    .addTag('images', 'Container image management and scanning')
    .addTag('cves', 'CVE (Common Vulnerabilities and Exposures) management')
    .build();

export const swaggerOptions = {
    swaggerOptions: {
        persistAuthorization: true,
    },
};

