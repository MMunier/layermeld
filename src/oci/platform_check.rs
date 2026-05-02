//! Platform consistency check (spec 08 §8.3).
//!
//! Before any dedup decision is made, the run inspects every input
//! image's `architecture`, `os`, and `variant`. If any pair of inputs
//! disagrees on any of those fields a single `tracing::warn!` event is
//! emitted to stderr listing each image's platform tuple and which
//! field(s) diverged. The run continues — sharing layers across
//! platforms is unusual but not strictly invalid (e.g. a pure-script
//! `noarch` image can be deduplicated with anything per spec §8.3); the
//! warning exists only so the user can abort if it was unintentional.
//!
//! The output is *not* turned into a multi-arch manifest list — spec 09
//! §9.2 lists each image independently with its own `platform`
//! annotation. Cross-platform dedup just means a shared blob may carry
//! bytes that several platforms happen to agree on byte-for-byte.

use oci_spec::image::ImageConfiguration;

/// One divergent input image's platform snapshot.
///
/// Carried through the warning payload so the user can map a divergence
/// back to the exact argv-position image. `architecture` and `os` are
/// rendered through `Display` (the same spelling as in the manifest
/// `Platform`); `variant` is `None` when the image config did not
/// populate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformSnapshot {
    /// Argv-position of the input image (matches
    /// [`crate::squash::index::InputImageId`]).
    pub idx: usize,
    /// `architecture` rendered as a string (e.g. `"amd64"`, `"arm64"`).
    pub architecture: String,
    /// `os` rendered as a string (e.g. `"linux"`, `"windows"`).
    pub os: String,
    /// `variant`, present only when the image config carried one
    /// (e.g. `"v8"` for `ARM64v8`).
    pub variant: Option<String>,
}

/// Detected divergence across the input set.
///
/// `fields` lists the subset of `{"architecture", "os", "variant"}` on
/// which the inputs disagree — sorted in that canonical order so the
/// warning text is deterministic across runs. `images` is the per-image
/// snapshot list in argv order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDivergence {
    /// Subset of `["architecture", "os", "variant"]`, in that order.
    pub fields: Vec<&'static str>,
    /// One snapshot per input image, in argv order.
    pub images: Vec<PlatformSnapshot>,
}

/// Inspect platform fields and return the divergence, if any.
///
/// Two images are *consistent* iff they agree on `architecture`, on `os`,
/// and on `variant` (with `None == None` and `Some(x) == Some(y) iff
/// x == y` — a missing variant differs from a present one). The result
/// is `None` for an empty input or a fully-consistent set; otherwise the
/// returned [`PlatformDivergence`] names the diverging fields and every
/// image's snapshot.
#[must_use]
pub fn detect_divergence(configs: &[&ImageConfiguration]) -> Option<PlatformDivergence> {
    let snapshots: Vec<PlatformSnapshot> = configs.iter().enumerate().map(|(i, c)| snapshot(i, c)).collect();
    if snapshots.len() < 2 {
        return None;
    }
    let first = &snapshots[0];
    let mut fields: Vec<&'static str> = Vec::new();
    if snapshots.iter().any(|s| s.architecture != first.architecture) {
        fields.push("architecture");
    }
    if snapshots.iter().any(|s| s.os != first.os) {
        fields.push("os");
    }
    if snapshots.iter().any(|s| s.variant != first.variant) {
        fields.push("variant");
    }
    if fields.is_empty() {
        None
    } else {
        Some(PlatformDivergence {
            fields,
            images: snapshots,
        })
    }
}

/// Run [`detect_divergence`] and emit a single `tracing::warn!` event
/// when divergence is found. Always continues — the spec §8.3 contract
/// is "warn, don't fail".
pub fn check_platform_consistency(configs: &[&ImageConfiguration]) {
    let Some(div) = detect_divergence(configs) else {
        return;
    };
    tracing::warn!(
        divergent_fields = %div.fields.join(","),
        images = %render_images(&div.images),
        "input images disagree on platform; sharing layers across platforms is allowed but unusual (spec 08 §8.3)",
    );
}

fn snapshot(idx: usize, cfg: &ImageConfiguration) -> PlatformSnapshot {
    PlatformSnapshot {
        idx,
        architecture: cfg.architecture().to_string(),
        os: cfg.os().to_string(),
        variant: cfg.variant().clone(),
    }
}

fn render_images(images: &[PlatformSnapshot]) -> String {
    let parts: Vec<String> = images
        .iter()
        .map(|s| {
            let variant = s.variant.as_deref().unwrap_or("-");
            format!("image-{}={}/{}/{}", s.idx, s.architecture, s.os, variant)
        })
        .collect();
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use oci_spec::image::{Arch, ImageConfigurationBuilder, Os, RootFsBuilder};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    fn cfg(arch: Arch, os: Os, variant: Option<&str>) -> ImageConfiguration {
        let mut b = ImageConfigurationBuilder::default()
            .architecture(arch)
            .os(os)
            .rootfs(RootFsBuilder::default().diff_ids(Vec::<String>::new()).build().unwrap());
        if let Some(v) = variant {
            b = b.variant(v.to_string());
        }
        b.build().unwrap()
    }

    /// Tracing subscriber sink that captures every formatted line into a
    /// shared `Vec<u8>`. Used to assert that the warning is actually
    /// emitted (and to inspect its payload).
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured<F: FnOnce()>(body: F) -> String {
        let writer = CaptureWriter::default();
        let buf = writer.0.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, body);
        let bytes = buf.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn empty_input_is_consistent() {
        assert!(detect_divergence(&[]).is_none());
    }

    #[test]
    fn single_image_is_trivially_consistent() {
        let c = cfg(Arch::Amd64, Os::Linux, None);
        assert!(detect_divergence(&[&c]).is_none());
    }

    #[test]
    fn fully_matching_pair_is_consistent() {
        let a = cfg(Arch::Amd64, Os::Linux, Some("v2"));
        let b = cfg(Arch::Amd64, Os::Linux, Some("v2"));
        assert!(detect_divergence(&[&a, &b]).is_none());
    }

    #[test]
    fn fully_matching_triple_with_no_variant_is_consistent() {
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::Amd64, Os::Linux, None);
        let c = cfg(Arch::Amd64, Os::Linux, None);
        assert!(detect_divergence(&[&a, &b, &c]).is_none());
    }

    #[test]
    fn architecture_divergence_is_flagged() {
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::ARM64, Os::Linux, None);
        let div = detect_divergence(&[&a, &b]).expect("divergent");
        assert_eq!(div.fields, vec!["architecture"]);
        assert_eq!(div.images.len(), 2);
        assert_eq!(div.images[0].architecture, "amd64");
        assert_eq!(div.images[1].architecture, "arm64");
    }

    #[test]
    fn os_divergence_is_flagged() {
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::Amd64, Os::Windows, None);
        let div = detect_divergence(&[&a, &b]).expect("divergent");
        assert_eq!(div.fields, vec!["os"]);
    }

    #[test]
    fn variant_present_vs_absent_is_flagged() {
        // None != Some("v8") — a missing variant counts as a difference.
        let a = cfg(Arch::ARM64, Os::Linux, None);
        let b = cfg(Arch::ARM64, Os::Linux, Some("v8"));
        let div = detect_divergence(&[&a, &b]).expect("divergent");
        assert_eq!(div.fields, vec!["variant"]);
        assert_eq!(div.images[0].variant, None);
        assert_eq!(div.images[1].variant.as_deref(), Some("v8"));
    }

    #[test]
    fn variant_value_difference_is_flagged() {
        let a = cfg(Arch::ARM64, Os::Linux, Some("v7"));
        let b = cfg(Arch::ARM64, Os::Linux, Some("v8"));
        let div = detect_divergence(&[&a, &b]).expect("divergent");
        assert_eq!(div.fields, vec!["variant"]);
    }

    #[test]
    fn multi_field_divergence_lists_canonical_order() {
        // arch + os + variant all differ — fields must be in canonical
        // order so the warning text is byte-stable across runs.
        let a = cfg(Arch::Amd64, Os::Linux, Some("v2"));
        let b = cfg(Arch::ARM64, Os::Windows, Some("v8"));
        let div = detect_divergence(&[&a, &b]).expect("divergent");
        assert_eq!(div.fields, vec!["architecture", "os", "variant"]);
    }

    #[test]
    fn three_images_one_outlier_is_flagged() {
        // Two images agree, the third differs on arch — still divergent.
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::Amd64, Os::Linux, None);
        let c = cfg(Arch::ARM64, Os::Linux, None);
        let div = detect_divergence(&[&a, &b, &c]).expect("divergent");
        assert_eq!(div.fields, vec!["architecture"]);
        // All three snapshots are reported, in argv order.
        assert_eq!(div.images.len(), 3);
        assert_eq!(div.images[0].idx, 0);
        assert_eq!(div.images[1].idx, 1);
        assert_eq!(div.images[2].idx, 2);
    }

    #[test]
    fn check_emits_no_warning_for_consistent_inputs() {
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::Amd64, Os::Linux, None);
        let out = captured(|| check_platform_consistency(&[&a, &b]));
        assert!(out.is_empty(), "expected no log output, got: {out}");
    }

    #[test]
    fn check_emits_one_warning_for_divergent_inputs() {
        let a = cfg(Arch::Amd64, Os::Linux, None);
        let b = cfg(Arch::ARM64, Os::Linux, None);
        let out = captured(|| check_platform_consistency(&[&a, &b]));
        assert!(out.contains("WARN"), "expected WARN level, got: {out}");
        assert!(out.contains("architecture"), "got: {out}");
        assert!(out.contains("image-0=amd64/linux/-"), "got: {out}");
        assert!(out.contains("image-1=arm64/linux/-"), "got: {out}");
        // Exactly one event — single warning per the spec.
        assert_eq!(out.matches("WARN").count(), 1, "got: {out}");
    }

    #[test]
    fn check_warning_includes_variant_when_present() {
        let a = cfg(Arch::ARM64, Os::Linux, Some("v8"));
        let b = cfg(Arch::ARM64, Os::Linux, None);
        let out = captured(|| check_platform_consistency(&[&a, &b]));
        assert!(out.contains("image-0=arm64/linux/v8"), "got: {out}");
        assert!(out.contains("image-1=arm64/linux/-"), "got: {out}");
        assert!(out.contains("variant"), "got: {out}");
    }

    #[test]
    fn check_no_warning_for_empty_or_singleton() {
        // Single-image runs cannot diverge — must stay silent.
        let c = cfg(Arch::Amd64, Os::Linux, None);
        let out_single = captured(|| check_platform_consistency(&[&c]));
        assert!(out_single.is_empty(), "got: {out_single}");
        let out_empty = captured(|| check_platform_consistency(&[]));
        assert!(out_empty.is_empty(), "got: {out_empty}");
    }
}
