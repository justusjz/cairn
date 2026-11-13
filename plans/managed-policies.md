# Managed policies, instead of grants

A draft, for discussion before any of it is built.

## Why

A tenant's access is set in three places today, and they look unrelated:

- **Grants** (`read`, `write`, `delete-version` on a bucket) are made on the
  Users page, but kept as statements of the *bucket's* policy, with Sids
  `CairnGrantRead`, `CairnGrantWrite` and `CairnGrantDeleteVersion`, each
  listing about 14 actions (`src/grants.rs`, `s3::actions::grant_actions`).
  So a bucket's policy, edited on the bucket's page, shows statements nobody
  wrote there, and editing them there changes what the Users page shows.
- **Admin** is a flag on the user, which stands for the one managed policy
  there is, `AdministratorAccess` (the IAM API attaches and detaches it).
- **Inline policies** are the user's own documents.

AWS has one model for this, and tools (Terraform, the AWS CLI, SDKs) expect
it: **identity policies**, managed (one document, attached to many users) or
inline (one user's own), plus bucket policies for what's about the bucket:
other accounts, public access, and guardrails (deny without TLS, and the
like). Within one account, an identity policy and a bucket policy that allow
the same thing are equivalent (`policy::verdict_across` already treats them
so). AWS ships prewritten policies (`AmazonS3ReadOnlyAccess`,
`AmazonS3FullAccess`), but they cover every bucket (`"Resource": "*"`); for
one bucket, its statements are written out, as Cairn's grants are.

## What

1. **Managed policies**, of two kinds, as in AWS:
   - **Cairn's own**, read-only, with AWS's names and ARNs, so that
     Terraform and policies written for AWS work unchanged:
     `arn:aws:iam::aws:policy/AdministratorAccess` (there already),
     `AmazonS3FullAccess` and `AmazonS3ReadOnlyAccess`.
   - **An account's own**: `arn:aws:iam::<account>:policy/<name>`, made,
     changed and deleted by its admins. A document is at most 6,144
     characters (but whitespace), as in IAM; a user has at most 10 attached
     (IAM's default quota). Versions (IAM keeps 5) can come later: until
     then, CreatePolicyVersion replaces the one version there is, and
     ListPolicyVersions lists it.

   The IAM API gets CreatePolicy, GetPolicy, GetPolicyVersion,
   CreatePolicyVersion, DeletePolicy, ListPolicies,
   ListEntitiesForPolicy, and AttachUserPolicy, DetachUserPolicy and
   ListAttachedUserPolicies for any policy, not just AdministratorAccess.
   Each is checked as IAM's action, on the policy's ARN.

2. **The admin flag becomes an attachment** of AdministratorAccess, like any
   other: `roles.admin` stays (older nodes read it) and is kept as whether
   that policy is attached. The console shows "admin" as a badge for it, not
   as a toggle of its own.

3. **Grants go away, as a concept.** On a user's page, "Add access" opens the
   policy editor with a template: pick buckets and a level, and it writes
   the statements (readably: `s3:GetObject*`-style patterns where they mean
   the same), as an inline policy or a new managed one. What's in effect is
   only ever what's attached, and what the bucket's policy says.

4. **A bucket's page shows who has access**: its policy, and, computed and
   kept nowhere, the account's users whose policies allow anything on it,
   and what (a small Access Analyzer). Nothing on the Users page writes a
   bucket's policy any more.

5. **Moving the grants there are.** For each bucket and permission that's
   granted, a managed policy of the account, `<bucket>-read` (`-write`,
   `-delete-version`), with that statement, attached to the users it names;
   then the `CairnGrant*` statements leave the bucket's policy. The effect
   is the same within the account (grants only ever named the bucket's own
   account's users), with one difference, as in AWS: a bucket deleted and
   made again under the same name is accessible again to whoever's policies
   name it, where a grant went away with its bucket.

6. **`cairn user grant` and `revoke`** stay, as shortcuts: they attach (and
   detach) those managed policies, making them if needed, so scripts keep
   working.

## Later

- **Groups** (on the roadmap): attach `invoices-read` to a group, not to
  each person. They're what makes managed policies pay off for people.
- **Permissions boundaries** (on the roadmap): what makes it safe to let
  a non-admin create users (`iam:CreateUser` with `iam:PermissionsBoundary`
  as a condition), as AWS delegates user management.

## Open questions

- Migrating grants into managed policies (one per bucket and level) or into
  each user's inline policy? Managed ones keep the console tidy and are
  shared; inline ones would hit the 2,048-character limit for users with
  many buckets. Managed, so far.
- Does the template write managed or inline policies by default? A person
  gets the same access as others more often than not (managed); a service
  user's is usually its own (inline).
- Should `AmazonS3FullAccess` include `s3:PutBucketPolicy` and the like, as
  AWS's does (`s3:*`)? Matching AWS seems right: it's what the name says.
