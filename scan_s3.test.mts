import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { scanSnapshot } from "./scan_s3.mts";
import publicReadSnapshot from "./fixtures/public-read.json" with { type: "json" };
import roleOnlySnapshot from "./fixtures/role-only-read.json" with { type: "json" };

const scannerPath = fileURLToPath(new URL("./scan_s3.mts", import.meta.url));

function scanFixture(name: string, expectedPrincipal: "*" | { AWS: string } = "*") {
  const fixturePath = fileURLToPath(new URL("./fixtures/" + name, import.meta.url));
  const output = execFileSync(process.execPath, [scannerPath, fixturePath], { encoding: "utf8" });
  const result = JSON.parse(output);

  assert.equal(result.bucket, "internal-reports-example");
  const statement = expectedPrincipal === "*"
    ? result.evidence.public_read_statement
    : result.evidence.role_read_statement;
  assert.ok(statement, "Expected the statement that explains the decision");
  assert.deepEqual(statement.Principal, expectedPrincipal);
  assert.equal(statement.Action, "s3:GetObject");
  assert.equal(statement.Resource, "arn:aws:s3:::internal-reports-example/*");
  assert.equal(result.evidence.public_access_block.bucket.RestrictPublicBuckets, false);

  return result;
}

test("reports a finding when neither level blocks the public grant", () => {
  const result = scanFixture("public-read.json");

  assert.equal(result.status, "FINDING");
  assert.equal(result.evidence.public_access_block.account.RestrictPublicBuckets, false);
  assert.match(result.remediation, /remove|limit/i);
});

test("reports no finding when the account blocks the same grant", () => {
  const result = scanFixture("account-blocks-public-read.json");

  assert.equal(result.status, "NO_FINDING");
  assert.equal(result.evidence.public_access_block.account.RestrictPublicBuckets, true);
  assert.deepEqual(result.evidence.blocking_levels, ["account"]);
});

test("reports unknown when the account setting could not be read", () => {
  const result = scanFixture("account-settings-denied.json");

  assert.equal(result.status, "UNKNOWN");
  assert.deepEqual(result.evidence.public_access_block.account, {
    RestrictPublicBuckets: null,
    error: "AccessDenied",
  });
  assert.deepEqual(result.evidence.unknown_levels, ["account"]);
});

test("reports no finding when the policy grants reads to one role", () => {
  const result = scanFixture("role-only-read.json", {
    AWS: "arn:aws:iam::123456789012:role/ReportsApp",
  });

  assert.equal(result.status, "NO_FINDING");
  assert.equal(result.evidence.public_access_block.account.RestrictPublicBuckets, false);
  assert.equal(result.evidence.public_read_statement, undefined);
  assert.equal(result.evidence.blocking_levels, undefined);
});

test("treats confirmed absence of Block Public Access configuration as off", () => {
  const error = "NoSuchPublicAccessBlockConfiguration";
  for (const level of ["bucket", "account"] as const) {
    const result = scanSnapshot({
      ...publicReadSnapshot,
      [level + "_public_access_block"]: { error },
    });

    assert.equal(result.status, "FINDING");
    assert.deepEqual(result.evidence.public_access_block[level], {
      RestrictPublicBuckets: false,
      source: error,
    });
  }
});

test("honors a proven bucket block when the account setting is unreadable", () => {
  const result = scanSnapshot({
    ...publicReadSnapshot,
    bucket_public_access_block: { RestrictPublicBuckets: true },
    account_public_access_block: { error: "AccessDenied" },
  });

  assert.equal(result.status, "NO_FINDING");
  assert.deepEqual(result.evidence.blocking_levels, ["bucket"]);
  assert.deepEqual(result.evidence.public_access_block.account, {
    RestrictPublicBuckets: null,
    error: "AccessDenied",
  });
});

test("accepts punctuation in an IAM role path", () => {
  const snapshot = structuredClone(roleOnlySnapshot);
  const roleArn = "arn:aws:iam::123456789012:role/team!reports/ReportsApp";
  snapshot.bucket_policy.Statement[0].Principal.AWS = roleArn;
  const result = scanSnapshot(snapshot);

  assert.equal(result.status, "NO_FINDING");
  assert.deepEqual(result.evidence.role_read_statement?.Principal, { AWS: roleArn });
});

test("keeps wildcard patterns in an IAM role ARN unknown", () => {
  const snapshot = structuredClone(roleOnlySnapshot);
  for (const path of ["team/Reports*", "team?/ReportsApp"]) {
    snapshot.bucket_policy.Statement[0].Principal.AWS = "arn:aws:iam::123456789012:role/" + path;
    assert.equal(scanSnapshot(snapshot).status, "UNKNOWN");
  }
});

test("accepts singleton arrays for the action and resource", () => {
  const [statement] = publicReadSnapshot.bucket_policy.Statement;
  const arrayStatement = {
    ...statement,
    Action: [statement.Action],
    Resource: [statement.Resource],
  };
  const result = scanSnapshot({
    ...publicReadSnapshot,
    bucket_policy: { ...publicReadSnapshot.bucket_policy, Statement: [arrayStatement] },
  });

  assert.equal(result.status, "FINDING");
  assert.deepEqual(result.evidence.public_read_statement, arrayStatement);
});

test("identifies an unreadable bucket policy and names the read permission", () => {
  const result = scanSnapshot({
    ...publicReadSnapshot,
    bucket_policy: { error: "AccessDenied" },
  });

  assert.ok(result.status === "UNKNOWN");
  assert.equal(result.evidence.bucket_policy_error, "AccessDenied");
  assert.match(result.reason, /could not be read.*AccessDenied/);
  assert.match(result.next_step ?? "", /s3:GetBucketPolicy/);
});

test("identifies an unsupported policy separately from a read error", () => {
  const [statement] = publicReadSnapshot.bucket_policy.Statement;
  const result = scanSnapshot({
    ...publicReadSnapshot,
    bucket_policy: {
      Statement: [{ ...statement, Action: [statement.Action, "s3:PutObject"] }],
    },
  });

  assert.equal(result.status, "UNKNOWN");
  assert.match(result.reason, /unsupported/);
  assert.equal(result.evidence.bucket_policy_error, undefined);
});

test("preserves no finding when S3 confirms the bucket policy is absent", () => {
  const result = scanSnapshot({
    ...publicReadSnapshot,
    bucket_policy: { error: "NoSuchBucketPolicy" },
  });

  assert.equal(result.status, "NO_FINDING");
  assert.equal(result.evidence.bucket_policy_error, "NoSuchBucketPolicy");
});
