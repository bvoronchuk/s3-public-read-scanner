import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

const levels = ["bucket", "account"] as const;
type Level = (typeof levels)[number];

type AccessBlock =
  | { RestrictPublicBuckets: boolean }
  | { RestrictPublicBuckets: false; source: "NoSuchPublicAccessBlockConfiguration" }
  | { RestrictPublicBuckets: null; error: string };

type ObjectReadGrant = {
  kind: "public" | "role";
  statement: Record<string, unknown>;
};

type Evidence = {
  public_access_block: Record<Level, AccessBlock>;
  bucket_policy_error?: string;
  public_read_statement?: Record<string, unknown>;
  role_read_statement?: Record<string, unknown>;
  blocking_levels?: Level[];
  unknown_levels?: Level[];
};

const ScanStatus = {
  Finding: "FINDING",
  NoFinding: "NO_FINDING",
  Unknown: "UNKNOWN",
} as const;

type ScanResult = {
  bucket: string;
  evidence: Evidence;
  reason: string;
} & (
  | { status: typeof ScanStatus.Finding; remediation: string }
  | { status: typeof ScanStatus.NoFinding }
  | { status: typeof ScanStatus.Unknown; next_step?: string }
);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readRestriction(response: unknown): AccessBlock {
  if (isRecord(response)) {
    const { error, RestrictPublicBuckets } = response;
    if (error === "NoSuchPublicAccessBlockConfiguration" && RestrictPublicBuckets === undefined) {
      return { RestrictPublicBuckets: false, source: error };
    }
    if (typeof error === "string" && error) {
      return { RestrictPublicBuckets: null, error };
    }
    if (typeof RestrictPublicBuckets === "boolean") {
      return { RestrictPublicBuckets };
    }
  }

  return { RestrictPublicBuckets: null, error: "Missing or invalid setting" };
}

function isNamedRoleArn(value: unknown): boolean {
  if (typeof value !== "string" || /[*?]|\$\{/.test(value)) {
    return false;
  }
  const resource = /^arn:aws:iam::\d{12}:role\/(.+)$/.exec(value)?.[1];
  if (!resource) {
    return false;
  }

  const nameStart = resource.lastIndexOf("/") + 1;
  const path = "/" + resource.slice(0, nameStart);
  const name = resource.slice(nameStart);
  return path.length <= 512 &&
    /^(?:\/|\/[\x21-\x7E]+\/)$/.test(path) &&
    /^[A-Za-z0-9_+=,.@-]{1,64}$/.test(name);
}

function unwrapSingleton(value: unknown): unknown {
  return Array.isArray(value) && value.length === 1 ? value[0] : value;
}

// Recognize one unconditional read grant to everyone or to a named IAM role.
function readObjectGrant(policy: unknown, objectArn: string): ObjectReadGrant | undefined {
  const policyKeys = ["Version", "Id", "Statement"];
  if (!isRecord(policy) || Object.keys(policy).some((key) => !policyKeys.includes(key))) {
    return;
  }

  const statement = unwrapSingleton(policy.Statement);
  const statementKeys = ["Sid", "Effect", "Principal", "Action", "Resource"];
  if (!isRecord(statement) || Object.keys(statement).some((key) => !statementKeys.includes(key))) {
    return;
  }

  const { Effect, Principal, Action, Resource } = statement;
  const action = unwrapSingleton(Action);
  if (
    Effect !== "Allow" ||
    typeof action !== "string" ||
    action.toLowerCase() !== "s3:getobject" ||
    unwrapSingleton(Resource) !== objectArn
  ) {
    return;
  }

  const awsPrincipal = isRecord(Principal) && Object.keys(Principal).length === 1
    ? Principal.AWS
    : undefined;
  if (Principal === "*" || awsPrincipal === "*") {
    return { kind: "public", statement };
  }

  if (isNamedRoleArn(awsPrincipal)) {
    return { kind: "role", statement };
  }
}

export function scanSnapshot(snapshot: unknown): ScanResult {
  if (!isRecord(snapshot)) {
    throw new Error("Snapshot must be a JSON object");
  }
  const bucketName = snapshot.bucket_name;
  if (typeof bucketName !== "string" || !bucketName.trim()) {
    throw new Error("Snapshot must include a non-empty bucket_name");
  }

  const restrictions = {
    bucket: readRestriction(snapshot.bucket_public_access_block),
    account: readRestriction(snapshot.account_public_access_block),
  };
  const evidence: Evidence = { public_access_block: restrictions };
  const result = { bucket: bucketName, evidence };

  const policy = snapshot.bucket_policy;
  const policyError = isRecord(policy) && typeof policy.error === "string" ? policy.error : undefined;
  if (policyError) {
    evidence.bucket_policy_error = policyError;
  }
  if (policyError === "NoSuchBucketPolicy") {
    return {
      ...result,
      status: ScanStatus.NoFinding,
      reason: "AWS reports that the bucket has no bucket policy.",
    };
  }
  if (policyError || policy === undefined || policy === null) {
    return {
      ...result,
      status: ScanStatus.Unknown,
      reason: policyError
        ? "The bucket policy could not be read (" + policyError + ")."
        : "The bucket policy was not collected.",
      next_step: "Check the S3 GetBucketPolicy response and the scanner role's s3:GetBucketPolicy permission.",
    };
  }

  const grant = readObjectGrant(policy, "arn:aws:s3:::" + bucketName + "/*");
  if (!grant) {
    return {
      ...result,
      status: ScanStatus.Unknown,
      reason: "The bucket policy uses an unsupported policy form.",
    };
  }

  if (grant.kind === "role") {
    evidence.role_read_statement = grant.statement;
    return {
      ...result,
      status: ScanStatus.NoFinding,
      reason: "The bucket policy grants GetObject only to a named IAM role.",
    };
  }

  evidence.public_read_statement = grant.statement;
  const blockingLevels = levels.filter((level) => restrictions[level].RestrictPublicBuckets === true);
  if (blockingLevels.length) {
    evidence.blocking_levels = blockingLevels;
    return {
      ...result,
      status: ScanStatus.NoFinding,
      reason: "RestrictPublicBuckets blocks anonymous reads through this policy.",
    };
  }

  const unknownLevels = levels.filter((level) => restrictions[level].RestrictPublicBuckets === null);
  if (unknownLevels.length) {
    evidence.unknown_levels = unknownLevels;
    return {
      ...result,
      status: ScanStatus.Unknown,
      reason: "RestrictPublicBuckets could not be determined at every required level.",
      next_step: "Check read permissions or the collection error, then refresh the snapshot.",
    };
  }

  return {
    ...result,
    status: ScanStatus.Finding,
    reason: "The policy grants anonymous GetObject and both RestrictPublicBuckets settings are off.",
    remediation: "Remove the public grant or limit it to the identities that need read access.",
  };
}

function main() {
  const usage = "Usage: node scan_s3.mts <snapshot.json>";
  try {
    const { values, positionals } = parseArgs({
      allowPositionals: true,
      options: { help: { type: "boolean", short: "h" } },
    });
    if (values.help) {
      console.log(usage);
      return;
    }
    const [snapshotPath] = positionals;
    if (!snapshotPath || positionals.length !== 1) {
      throw new Error("Provide exactly one snapshot path.");
    }

    const contents = readFileSync(snapshotPath, "utf8").replace(/^\uFEFF/, "");
    const snapshot: unknown = JSON.parse(contents);
    console.log(JSON.stringify(scanSnapshot(snapshot), null, 2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(usage);
    console.error("scan_s3: " + message);
    process.exitCode = 2;
  }
}

if (import.meta.main) {
  main();
}
