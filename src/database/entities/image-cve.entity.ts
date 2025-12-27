import { Column, CreateDateColumn, Entity, Index, JoinColumn, ManyToOne, PrimaryGeneratedColumn, Unique } from "typeorm";
import { Image } from "./image.entity";
import { Cve } from "./cve.entity";

@Entity('image_cves')
@Unique('UQ_image_cves_image_cve_package', ['imageId', 'cveId', 'packageName'])
export class ImageCve {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Index('IDX_image_cves_image_id')
    @Column({ name: 'image_id', type: 'uuid' })
    imageId: string;

    @Index('IDX_image_cves_cve_id')
    @Column({ name: 'cve_id', type: 'uuid' })
    cveId: string;

    @Column({ name: 'package_name', type: 'varchar', length: 255 })
    packageName: string;

    @Column({ name: 'installed_version', type: 'varchar', length: 100, nullable: true })
    installedVersion: string | null;

    @Column({ name: 'fixed_version', type: 'varchar', length: 100, nullable: true })
    fixedVersion: string | null;

    @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
    createdAt: Date;

    @ManyToOne(() => Image, (image) => image.imageCves, { onDelete: 'CASCADE' })
    @JoinColumn({ name: 'image_id' })
    image: Image;

    @ManyToOne(() => Cve, (cve) => cve.imageCves, { onDelete: 'CASCADE' })
    @JoinColumn({ name: 'cve_id' })
    cve: Cve;
}
