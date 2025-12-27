import { Column, CreateDateColumn, Entity, Index, OneToMany, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";
import { ImageCve } from "./image-cve.entity";

export enum ImageStatus {
    PENDING = 'pending',
    SCANNING = 'scanning',
    COMPLETED = 'completed',
    FAILED = 'failed'
}

@Entity('images')
@Index('IDX_images_name_tag', ['name', 'tag'], { unique: true })
export class Image {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ type: 'varchar', length: 255 })
    name: string;

    @Column({ type: 'varchar', length: 128 })
    tag: string;

    @Column({
        type: 'enum',
        enum: ImageStatus,
        default: ImageStatus.PENDING
    })
    status: ImageStatus;

    @Column({ name: 'last_scanned_at', type: 'timestamptz', nullable: true })
    lastScannedAt: Date | null;

    @Column({ name: 'error_message', type: 'text', nullable: true })
    errorMessage: string | null;

    @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
    createdAt: Date;

    @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
    updatedAt: Date;

    @OneToMany(() => ImageCve, (imageCve) => imageCve.image)
    imageCves: ImageCve[];

    get fullName(): string {
        return `${this.name}:${this.tag}`;
    }
}