//! AWS KMS's actions and condition keys (AWS's service authorization
//! reference for KMS), which keys' policies name, and identity policies
//! may (see `kms`).

pub const ACTIONS: &[&str] = &[
    "CancelKeyDeletion",
    "ConnectCustomKeyStore",
    "CreateAlias",
    "CreateCustomKeyStore",
    "CreateGrant",
    "CreateKey",
    "Decrypt",
    "DeleteAlias",
    "DeleteCustomKeyStore",
    "DeleteImportedKeyMaterial",
    "DeriveSharedSecret",
    "DescribeCustomKeyStores",
    "DescribeKey",
    "DisableKey",
    "DisableKeyRotation",
    "DisconnectCustomKeyStore",
    "EnableKey",
    "EnableKeyRotation",
    "Encrypt",
    "GenerateDataKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
    "GenerateDataKeyWithoutPlaintext",
    "GenerateMac",
    "GenerateRandom",
    "GetKeyPolicy",
    "GetKeyRotationStatus",
    "GetParametersForImport",
    "GetPublicKey",
    "ImportKeyMaterial",
    "ListAliases",
    "ListGrants",
    "ListKeyPolicies",
    "ListKeyRotations",
    "ListKeys",
    "ListResourceTags",
    "ListRetirableGrants",
    "PutKeyPolicy",
    "ReEncryptFrom",
    "ReEncryptTo",
    "ReplicateKey",
    "RetireGrant",
    "RevokeGrant",
    "RotateKeyOnDemand",
    "ScheduleKeyDeletion",
    "Sign",
    "SynchronizeMultiRegionKey",
    "TagResource",
    "UntagResource",
    "UpdateAlias",
    "UpdateCustomKeyStore",
    "UpdateKeyDescription",
    "UpdatePrimaryRegion",
    "Verify",
    "VerifyMac",
];

/// KMS's condition keys that Cairn's requests carry when KMS's would,
/// lowercase; a trailing `:` takes any suffix (an encryption context's key).
pub const EVALUATED_KEYS: &[&str] = &[
    "kms:bypasspolicylockoutsafetycheck",
    "kms:calleraccount",
    "kms:customermasterkeyspec",
    "kms:customermasterkeyusage",
    "kms:encryptionalgorithm",
    "kms:encryptioncontext:",
    "kms:encryptioncontextkeys",
    "kms:keyorigin",
    "kms:keyspec",
    "kms:keyusage",
    "kms:multiregion",
    "kms:reencryptonsamekey",
    "kms:requestalias",
    "kms:resourcealiases",
    "kms:rotationperiodindays",
    "kms:schedulekeydeletionpendingwindowindays",
    "kms:viaservice",
];

/// KMS's condition keys that no request to Cairn ever has: of grants, of
/// asymmetric, HMAC and imported keys, and of multi-Region ones, none of
/// which Cairn has.
pub const ABSENT_KEYS: &[&str] = &[
    "kms:datakeypairspec",
    "kms:expirationmodel",
    "kms:grantconstrainttype",
    "kms:grantisforawsresource",
    "kms:grantoperations",
    "kms:granteeprincipal",
    "kms:keyagreementalgorithm",
    "kms:macalgorithm",
    "kms:messagetype",
    "kms:multiregionkeytype",
    "kms:primaryregion",
    "kms:replicaregion",
    "kms:retiringprincipal",
    "kms:signingalgorithm",
    "kms:validto",
    "kms:wrappingalgorithm",
    "kms:wrappingkeyspec",
];

/// How a `kms:` condition key is supported: `None` if KMS has no such key.
pub fn support(key: &str) -> Option<super::condition::Support> {
    use super::condition::Support;
    let key = key.to_ascii_lowercase();
    let named = |entry: &&str| match entry.strip_suffix(':') {
        Some(_) => key.len() > entry.len() && key.starts_with(entry),
        None => key == *entry,
    };
    if EVALUATED_KEYS.iter().any(named) {
        return Some(Support::Evaluated);
    }
    if ABSENT_KEYS.iter().any(named) {
        return Some(Support::Absent);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::condition::Support;

    #[test]
    fn kms_keys_are_known() {
        assert_eq!(support("kms:ViaService"), Some(Support::Evaluated));
        assert_eq!(
            support("kms:EncryptionContext:aws:s3:arn"),
            Some(Support::Evaluated)
        );
        assert_eq!(support("kms:EncryptionContext:"), None);
        assert_eq!(support("kms:GrantOperations"), Some(Support::Absent));
        assert_eq!(support("kms:Frobnicate"), None);
    }
}
