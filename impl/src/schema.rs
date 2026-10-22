//! Validation of CBOR objects against the specification's CDDL
//! (spec/schemas/*.cddl), with the `cddl` crate. As in tools/check.py,
//! the schema files are concatenated with a root rule in front.

use anyhow::{anyhow, Result};

const CDDL: [&str; 5] = [
    include_str!("../../spec/schemas/common.cddl"),
    include_str!("../../spec/schemas/discovery.cddl"),
    include_str!("../../spec/schemas/credentials.cddl"),
    include_str!("../../spec/schemas/mls.cddl"),
    include_str!("../../spec/schemas/evidence.cddl"),
];

/// Validate `cbor` against the CDDL rule `rule`.
pub fn validate(rule: &str, cbor: &[u8]) -> Result<()> {
    let mut src = format!("scc-root = {rule}\n");
    for f in CDDL {
        src.push_str(f);
        src.push('\n');
    }
    cddl::validate_cbor_from_slice(&src, cbor, None).map_err(|e| anyhow!("does not match CDDL rule {rule}: {e}"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn spec_examples_validate() {
        let ex = concat!(env!("CARGO_MANIFEST_DIR"), "/../spec/examples/");
        for (f, rule) in [
            ("evidence-e1.cbor", "evidence-artefact"),
            ("decryption-report.cbor", "signed-decryption-report"),
            ("app-message.cbor", "app-message"),
        ] {
            let data = std::fs::read(format!("{ex}{f}")).unwrap();
            super::validate(rule, &data).unwrap_or_else(|e| panic!("{f}: {e}"));
        }
        assert!(super::validate("app-message", &[0xa0]).is_err());
    }
}
