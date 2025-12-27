import { registerAs } from '@nestjs/config';

export interface ImageConfig {
    name: string;
    tag: string;
}

export default registerAs('images', (): ImageConfig[] => [
    { name: 'nginx', tag: '1.19' },
    { name: 'postgres', tag: '12' },
    { name: 'redis', tag: '6.0' },
    { name: 'node', tag: '14-alpine' },
    { name: 'python', tag: '3.8-slim' },
    { name: 'alpine', tag: '3.12' },
    { name: 'ubuntu', tag: '20.04' },
    { name: 'mysql', tag: '8.0' },
    { name: 'mongo', tag: '4.4' },
    { name: 'httpd', tag: '2.4' },
]);