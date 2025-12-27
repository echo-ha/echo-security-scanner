import { MigrationInterface, QueryRunner } from "typeorm";

export class InitialSchema1766748652117 implements MigrationInterface {
    name = 'InitialSchema1766748652117'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TYPE "public"."cves_severity_enum" AS ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')`);
        await queryRunner.query(`CREATE TABLE "cves" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "cve_id" character varying(50) NOT NULL, "severity" "public"."cves_severity_enum" NOT NULL DEFAULT 'UNKNOWN', "title" character varying(500), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_f6d70ea4d7061ceff7ba1fe05a2" UNIQUE ("cve_id"), CONSTRAINT "PK_801487c3969cf1e5d7fb304dc37" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_cves_severity" ON "cves" ("severity") `);
        await queryRunner.query(`CREATE TABLE "image_cves" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "image_id" uuid NOT NULL, "cve_id" uuid NOT NULL, "package_name" character varying(255) NOT NULL, "installed_version" character varying(100), "fixed_version" character varying(100), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "UQ_image_cves_image_cve_package" UNIQUE ("image_id", "cve_id", "package_name"), CONSTRAINT "PK_640ec0f7e826730007d18b5fe4f" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE INDEX "IDX_image_cves_image_id" ON "image_cves" ("image_id") `);
        await queryRunner.query(`CREATE INDEX "IDX_image_cves_cve_id" ON "image_cves" ("cve_id") `);
        await queryRunner.query(`CREATE TYPE "public"."images_status_enum" AS ENUM('pending', 'scanning', 'completed', 'failed')`);
        await queryRunner.query(`CREATE TABLE "images" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" character varying(255) NOT NULL, "tag" character varying(128) NOT NULL, "status" "public"."images_status_enum" NOT NULL DEFAULT 'pending', "last_scanned_at" TIMESTAMP WITH TIME ZONE, "error_message" text, "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), CONSTRAINT "PK_1fe148074c6a1a91b63cb9ee3c9" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE UNIQUE INDEX "IDX_images_name_tag" ON "images" ("name", "tag") `);
        await queryRunner.query(`ALTER TABLE "image_cves" ADD CONSTRAINT "FK_f3683cd0336231b750ccaf931f6" FOREIGN KEY ("image_id") REFERENCES "images"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
        await queryRunner.query(`ALTER TABLE "image_cves" ADD CONSTRAINT "FK_a12c4fb9fc7f744c92b96880464" FOREIGN KEY ("cve_id") REFERENCES "cves"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "image_cves" DROP CONSTRAINT "FK_a12c4fb9fc7f744c92b96880464"`);
        await queryRunner.query(`ALTER TABLE "image_cves" DROP CONSTRAINT "FK_f3683cd0336231b750ccaf931f6"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_images_name_tag"`);
        await queryRunner.query(`DROP TABLE "images"`);
        await queryRunner.query(`DROP TYPE "public"."images_status_enum"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_image_cves_cve_id"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_image_cves_image_id"`);
        await queryRunner.query(`DROP TABLE "image_cves"`);
        await queryRunner.query(`DROP INDEX "public"."IDX_cves_severity"`);
        await queryRunner.query(`DROP TABLE "cves"`);
        await queryRunner.query(`DROP TYPE "public"."cves_severity_enum"`);
    }

}
