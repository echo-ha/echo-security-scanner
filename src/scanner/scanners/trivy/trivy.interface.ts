export interface TrivyVulnerability {
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion: string;
    FixedVersion?: string;
    Severity: string;
    Title?: string;
}

export interface TrivyResult {
    Target: string;
    Class?: string;
    Type?: string;
    Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyOutput {
    SchemaVersion?: number;
    ArtifactName?: string;
    ArtifactType?: string;
    Results?: TrivyResult[];
}