import { Column, CreateDateColumn, Entity, Index, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { ImageCve } from "./image-cve.entity";

export enum Severity {
    CRITICAL = 'CRITICAL',
    HIGH = 'HIGH',
    MEDIUM = 'MEDIUM',
    LOW = 'LOW',
    UNKNOWN = 'UNKNOWN',
}

@Entity('cves')

export class Cve {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ name: 'cve_id', type: 'varchar', length: 50, unique: true })
    cveId: string;

    @Index('IDX_cves_severity')
    @Column({ type: 'enum', enum: Severity, default: Severity.UNKNOWN })
    severity: Severity;

    @Column({ type: 'varchar', length: 500, nullable: true })
    title: string | null;

    @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
    updatedAt: Date;

    @OneToMany(() => ImageCve, (imageCve) => imageCve.cve)
    imageCves: ImageCve[];
}