//! Run-summary formatting (spec 10 §10.6).
//!
//! [`Summary`] is the data structure `lib::run` populates after a
//! successful (or `--dry-run`) pipeline pass; its [`fmt::Display`]
//! impl reproduces the human-readable block prescribed by spec 10
//! §10.6 verbatim. The format is **not** part of the determinism
//! contract (spec 10 §10.6 last paragraph) — it is for humans, and
//! machine-readable output is intentionally not emitted by default.
//!
//! The summary is written to stdout *after* the output has been
//! atomically renamed into place (spec 10 §10.8), so its presence is
//! a reliable "the artifact exists at the named path" signal for
//! scripts. `--quiet` suppression is handled by the caller, not here.
//!
//! ## Per-column derivation
//!
//! * `size` is each [`LayerSummary::size`] — the on-disk tar bytes of
//!   the emitted blob (spec 07's [`crate::assemble::EmittedLayer`]).
//! * `vs-naive` is `(|M| − 1) · size` for shared layers (`|M| ≥ 2`),
//!   the bytes that would have been duplicated across images if the
//!   layer hadn't been shared (spec 10 §10.6); per-image layers
//!   (`|M| == 1`) render as `—` since they are never deduplicated.
//! * `inputs total (squashed)` = Σ `|M| · size` over all output
//!   layers — the bytes you would have written if every image kept
//!   its own copy of every layer.
//! * `outputs total (deduplicated)` = Σ `size` — the actual bytes on
//!   disk after dedup.
//! * `saved` is the difference, plus a percentage rounded to one
//!   decimal place. The two definitions agree algebraically because
//!   `Σ (|M|−1)·size = Σ |M|·size − Σ size`.

use std::fmt;
use std::path::PathBuf;

use crate::assemble::emit::EmittedLayer;
use crate::cli::Layout;
use crate::dedup::membership::ImageSet;
use crate::squash::index::InputImageId;
use crate::timestamp::T0;

/// Aggregated post-run statistics in the shape spec 10 §10.6
/// formats. Built by `lib::run` once every blob has been finalised
/// and the output renamed into place.
#[derive(Debug, Clone)]
pub struct Summary {
    /// One entry per input image, in [`InputImageId`] order. The
    /// `[N]` index in the rendered output is the position in this
    /// vector, matching `image_id`.
    pub inputs: Vec<InputSummary>,
    /// Output destination as the user requested it (post-rename).
    pub output_path: PathBuf,
    /// Whether the layout was packed into a tar or left as a directory
    /// tree. Renders as the parenthetical "(oci layout: <path>)" /
    /// "(oci layout tar: <path>)" prefix on the outputs section.
    pub output_layout: Layout,
    /// Output layers in the spec 11 §11.6 lex-on-`ImageSet`
    /// iteration order [`crate::assemble::emit_layers`] returns.
    pub layers: Vec<LayerSummary>,
    /// Manifest digest produced for each input image, in `image_id`
    /// order. The label here is repeated from [`InputSummary::label`]
    /// so the per-image manifest section reads top-to-bottom without
    /// the user having to cross-reference indices.
    pub image_manifests: Vec<ImageManifestSummary>,
    /// Run-wide invocation timestamp (spec 06 §6.1). Rendered as
    /// RFC 3339 UTC via [`T0::to_rfc3339`].
    pub t0: T0,
}

/// Per-input-image accounting for the `inputs:` section of the
/// summary (spec 10 §10.6).
#[derive(Debug, Clone)]
pub struct InputSummary {
    /// `[N]` index in the rendered output. Matches the image's
    /// position in the run's argv-derived input list.
    pub image_id: InputImageId,
    /// Display label — the first repo tag if any, otherwise
    /// `<untagged>` (spec 09 §9.2 dir-transport case). Callers can
    /// pass any string here; this module never re-derives it.
    pub label: String,
    /// Number of input layers for the image (post-`oci-spec`
    /// parse, pre-squash).
    pub layer_count: usize,
    /// Sum of input layer sizes in bytes (compressed, as recorded
    /// on each manifest descriptor).
    pub total_bytes: u64,
}

/// Per-output-layer row in the `layers:` table.
#[derive(Debug, Clone)]
pub struct LayerSummary {
    /// Membership the layer was assembled for (spec 05 §5.4).
    /// Renders as either `shared {i,j,...}` (`|M| ≥ 2`) or
    /// `per-image {i}` (`|M| == 1`).
    pub membership: ImageSet,
    /// On-disk tar bytes of the emitted blob.
    pub size: u64,
    /// `sha256:<hex>` of the uncompressed tar — the layer's
    /// `diff_id` (spec 07 §7.3). For uncompressed output layers
    /// this is byte-equal to the blob's digest.
    pub diff_id: String,
}

impl LayerSummary {
    /// Project the spec 07 [`EmittedLayer`] into a row for the
    /// summary table. The full `sha256:<hex>` form is used for
    /// `diff_id`; the renderer truncates it for display.
    #[must_use]
    pub fn from_emitted(emitted: &EmittedLayer) -> Self {
        Self {
            membership: emitted.membership.clone(),
            size: emitted.size,
            diff_id: format!("sha256:{}", emitted.digest_hex()),
        }
    }
}

/// Per-image manifest digest for the `images:` section.
#[derive(Debug, Clone)]
pub struct ImageManifestSummary {
    /// Image position; matches [`InputSummary::image_id`].
    pub image_id: InputImageId,
    /// Display label — the same string used in [`InputSummary::label`].
    pub label: String,
    /// Manifest blob digest as `sha256:<hex>`.
    pub manifest_digest: String,
}

impl Summary {
    /// Total input bytes if every image kept its own copy of every
    /// output layer — i.e. Σ `|M| · size` over all layers.
    #[must_use]
    pub fn inputs_total_bytes(&self) -> u64 {
        self.layers
            .iter()
            .map(|l| l.size.saturating_mul(l.membership.len() as u64))
            .sum()
    }

    /// Total bytes actually written to disk — Σ `size` over all
    /// emitted layers.
    #[must_use]
    pub fn outputs_total_bytes(&self) -> u64 {
        self.layers.iter().map(|l| l.size).sum()
    }

    /// Bytes saved by dedup, equal to
    /// `inputs_total_bytes() - outputs_total_bytes()`.
    #[must_use]
    pub fn saved_bytes(&self) -> u64 {
        self.inputs_total_bytes().saturating_sub(self.outputs_total_bytes())
    }

    /// Bytes saved as tenths-of-a-percent (so `405` ⇒ "40.5%"),
    /// rounded to nearest. Integer-only arithmetic so a near-`u64::MAX`
    /// total cannot lose precision through an `f64` cast. Returns `0`
    /// if there is no input (avoids divide-by-zero on the empty-run
    /// edge case).
    #[must_use]
    pub fn saved_permille(&self) -> u64 {
        let total = self.inputs_total_bytes();
        if total == 0 {
            return 0;
        }
        // `saved · 1000 / total`, rounded half-up. Saturating ops
        // keep the math defined for the absurd-but-defensible
        // near-`u64::MAX` case.
        let scaled = self.saved_bytes().saturating_mul(1000);
        scaled.saturating_add(total / 2) / total
    }
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "layermeld run summary")?;

        writeln!(f, "  inputs:")?;
        for input in &self.inputs {
            writeln!(
                f,
                "    [{}] {:<28} (1 image, {} layers, {} bytes)",
                input.image_id.0, input.label, input.layer_count, input.total_bytes
            )?;
        }

        let layout_label = match self.output_layout {
            Layout::Tar => "oci layout tar",
            Layout::Dir => "oci layout dir",
        };
        writeln!(f, "  outputs ({}: {}):", layout_label, self.output_path.display())?;
        writeln!(
            f,
            "    layers:                       size           vs-naive       diff_id"
        )?;
        for layer in &self.layers {
            let label = membership_label(&layer.membership);
            let vs_naive = vs_naive_label(&layer.membership, layer.size);
            writeln!(
                f,
                "      {label:<24}    {size:<12}   {vs_naive:<12}   {diff}",
                size = layer.size,
                vs_naive = vs_naive,
                diff = truncate_digest(&layer.diff_id)
            )?;
        }

        writeln!(f, "    images:")?;
        for img in &self.image_manifests {
            writeln!(f, "      {} -> manifest {}", img.label, img.manifest_digest)?;
        }

        writeln!(f, "  bytes summary:")?;
        writeln!(f, "    inputs total (squashed):      {}", self.inputs_total_bytes())?;
        writeln!(f, "    outputs total (deduplicated): {}", self.outputs_total_bytes())?;
        let pm = self.saved_permille();
        writeln!(
            f,
            "    saved:                        {}  ({}.{}%)",
            self.saved_bytes(),
            pm / 10,
            pm % 10
        )?;

        write!(f, "  T0 = {}", self.t0.to_rfc3339())?;
        Ok(())
    }
}

/// Render an [`ImageSet`] as a comma-separated list inside braces:
/// `{0,1,2}`. Order is the set's intrinsic ascending order, which
/// is canonical thanks to [`ImageSet`]'s sorted-`Vec` backing.
fn brace_list(m: &ImageSet) -> String {
    let mut s = String::from("{");
    let mut first = true;
    for id in m.iter() {
        if !first {
            s.push(',');
        }
        first = false;
        s.push_str(&id.0.to_string());
    }
    s.push('}');
    s
}

/// `shared {i,j,...}` for `|M| ≥ 2`, `per-image {i}` for `|M| == 1`,
/// `empty {}` for `|M| == 0` (not produced by the dedup pipeline,
/// but defensible-against rather than panicking).
fn membership_label(m: &ImageSet) -> String {
    let braces = brace_list(m);
    match m.len() {
        0 => format!("empty {braces}"),
        1 => format!("per-image {braces}"),
        _ => format!("shared {braces}"),
    }
}

/// `+(|M|−1)·size` for shared layers; the em-dash for per-image
/// (and empty) layers, which are never deduplicated against
/// anything (spec 10 §10.6).
fn vs_naive_label(m: &ImageSet, size: u64) -> String {
    if m.len() < 2 {
        return "—".to_string();
    }
    let factor = (m.len() - 1) as u64;
    format!("+{}", size.saturating_mul(factor))
}

/// Render a `sha256:<64-hex>` digest as `sha256:<first-12>…` for
/// the `diff_id` column. The rendered summary is for humans, so
/// the truncated form is plenty to eyeball-distinguish blobs; the
/// untruncated digest is recoverable from the `blobs/sha256/`
/// directory of the output layout.
fn truncate_digest(digest: &str) -> String {
    if let Some(rest) = digest.strip_prefix("sha256:")
        && rest.len() > 12
    {
        return format!("sha256:{}…", &rest[..12]);
    }
    digest.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(id: usize) -> InputImageId {
        InputImageId(id)
    }

    fn set(ids: &[usize]) -> ImageSet {
        ImageSet::from_ids(ids.iter().copied().map(InputImageId))
    }

    fn fixture_summary() -> Summary {
        Summary {
            inputs: vec![
                InputSummary {
                    image_id: img(0),
                    label: "postgres:17.9-trixie".into(),
                    layer_count: 5,
                    total_bytes: 100_000_000,
                },
                InputSummary {
                    image_id: img(1),
                    label: "postgres:18.3-trixie".into(),
                    layer_count: 6,
                    total_bytes: 110_000_000,
                },
            ],
            output_path: PathBuf::from("/tmp/out.tar"),
            output_layout: Layout::Tar,
            layers: vec![
                LayerSummary {
                    membership: set(&[0, 1]),
                    size: 1_000_000,
                    diff_id: "sha256:aaaaaaaaaaaabbbbbbbbbbbbccccccccccccdddddddddddd11112222".into(),
                },
                LayerSummary {
                    membership: set(&[0]),
                    size: 200_000,
                    diff_id: "sha256:1111222233334444555566667777888899990000aaaabbbbccccdddd".into(),
                },
                LayerSummary {
                    membership: set(&[1]),
                    size: 300_000,
                    diff_id: "sha256:eeeeffffaaaa1111222233334444555566667777888899990000aaaa".into(),
                },
            ],
            image_manifests: vec![
                ImageManifestSummary {
                    image_id: img(0),
                    label: "postgres:17.9-trixie".into(),
                    manifest_digest: "sha256:cafebabe11112222".into(),
                },
                ImageManifestSummary {
                    image_id: img(1),
                    label: "postgres:18.3-trixie".into(),
                    manifest_digest: "sha256:cafebabe33334444".into(),
                },
            ],
            t0: T0::from_unix_seconds(1_700_000_000),
        }
    }

    #[test]
    fn brace_list_renders_ascending() {
        assert_eq!(brace_list(&set(&[2, 0, 1])), "{0,1,2}");
        assert_eq!(brace_list(&set(&[7])), "{7}");
        assert_eq!(brace_list(&ImageSet::new()), "{}");
    }

    #[test]
    fn membership_label_per_image_for_singleton() {
        assert_eq!(membership_label(&set(&[3])), "per-image {3}");
    }

    #[test]
    fn membership_label_shared_for_two_or_more() {
        assert_eq!(membership_label(&set(&[0, 1])), "shared {0,1}");
        assert_eq!(membership_label(&set(&[0, 1, 2])), "shared {0,1,2}");
    }

    #[test]
    fn membership_label_empty_set_renders_without_panic() {
        assert_eq!(membership_label(&ImageSet::new()), "empty {}");
    }

    #[test]
    fn vs_naive_em_dash_for_per_image() {
        assert_eq!(vs_naive_label(&set(&[0]), 1_000), "—");
    }

    #[test]
    fn vs_naive_em_dash_for_empty() {
        assert_eq!(vs_naive_label(&ImageSet::new(), 1_000), "—");
    }

    #[test]
    fn vs_naive_factor_is_size_times_membership_minus_one() {
        // |M|=2 -> factor 1
        assert_eq!(vs_naive_label(&set(&[0, 1]), 100), "+100");
        // |M|=3 -> factor 2
        assert_eq!(vs_naive_label(&set(&[0, 1, 2]), 100), "+200");
        // |M|=5 -> factor 4
        assert_eq!(vs_naive_label(&set(&[0, 1, 2, 3, 4]), 25), "+100");
    }

    #[test]
    fn vs_naive_handles_overflow_gracefully() {
        // Hypothetical: |M|=3 (factor 2) and size near u64::MAX. We
        // saturate rather than panic — the summary is for humans, so
        // a saturating value is more useful than an arithmetic abort.
        let huge = u64::MAX / 2 + 1;
        let label = vs_naive_label(&set(&[0, 1, 2]), huge);
        assert!(label.starts_with('+'));
        // Saturation lands at u64::MAX.
        assert_eq!(label, format!("+{}", u64::MAX));
    }

    #[test]
    fn truncate_digest_trims_long_hex() {
        let d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(truncate_digest(d), "sha256:0123456789ab…");
    }

    #[test]
    fn truncate_digest_preserves_short_input() {
        // Anything not matching `sha256:<long-hex>` is passed through
        // verbatim — defensive against a pre-truncated test fixture.
        assert_eq!(truncate_digest("sha256:abc"), "sha256:abc");
        assert_eq!(truncate_digest("opaque"), "opaque");
    }

    #[test]
    fn totals_inputs_outputs_saved() {
        let s = fixture_summary();
        // Σ |M|·size = 2·1_000_000 + 1·200_000 + 1·300_000 = 2_500_000
        assert_eq!(s.inputs_total_bytes(), 2_500_000);
        // Σ size = 1_000_000 + 200_000 + 300_000 = 1_500_000
        assert_eq!(s.outputs_total_bytes(), 1_500_000);
        // Saved = 1_000_000
        assert_eq!(s.saved_bytes(), 1_000_000);
        // 1_000_000 / 2_500_000 = 40.0% = 400 per-mille
        assert_eq!(s.saved_permille(), 400);
    }

    #[test]
    fn saved_permille_zero_input_is_zero() {
        let mut s = fixture_summary();
        s.layers.clear();
        assert_eq!(s.inputs_total_bytes(), 0);
        assert_eq!(s.saved_permille(), 0);
    }

    #[test]
    fn saved_permille_rounds_half_up() {
        // 1 saved out of 7 = 142.857… per-mille, rounds to 143.
        let s = Summary {
            inputs: Vec::new(),
            output_path: PathBuf::from("/tmp/x"),
            output_layout: Layout::Tar,
            layers: vec![LayerSummary {
                membership: set(&[0, 1, 2, 3, 4, 5, 6]),
                size: 1,
                diff_id: "sha256:0".into(),
            }],
            image_manifests: Vec::new(),
            t0: T0::from_unix_seconds(0),
        };
        // Σ |M|·size = 7, Σ size = 1, saved = 6, per-mille = 6000/7 ≈ 857.14 → 857
        assert_eq!(s.saved_permille(), 857);
    }

    #[test]
    fn from_emitted_projects_correctly() {
        use crate::assemble::emit::EmittedLayer;
        let digest = [0xaa; 32];
        let emitted = EmittedLayer {
            membership: set(&[0, 2]),
            digest,
            size: 4096,
            path: PathBuf::from("/scratch/blobs/sha256/aa"),
        };
        let row = LayerSummary::from_emitted(&emitted);
        assert_eq!(row.membership, set(&[0, 2]));
        assert_eq!(row.size, 4096);
        // Check the diff_id starts with "sha256:" and matches the
        // hex form of the digest.
        assert!(row.diff_id.starts_with("sha256:"));
        assert!(row.diff_id.ends_with("aa"));
        assert_eq!(row.diff_id.len(), 7 + 64);
    }

    #[test]
    fn display_contains_all_required_sections() {
        let out = fixture_summary().to_string();
        assert!(out.starts_with("layermeld run summary"));
        assert!(out.contains("inputs:"));
        assert!(out.contains("[0] postgres:17.9-trixie"));
        assert!(out.contains("[1] postgres:18.3-trixie"));
        assert!(out.contains("outputs ("));
        assert!(out.contains("/tmp/out.tar"));
        assert!(out.contains("oci layout tar"));
        assert!(out.contains("layers:"));
        assert!(out.contains("shared {0,1}"));
        assert!(out.contains("per-image {0}"));
        assert!(out.contains("per-image {1}"));
        assert!(out.contains("images:"));
        assert!(out.contains("postgres:17.9-trixie -> manifest sha256:cafebabe11112222"));
        assert!(out.contains("bytes summary:"));
        assert!(out.contains("inputs total (squashed):"));
        assert!(out.contains("outputs total (deduplicated):"));
        assert!(out.contains("saved:"));
        assert!(out.contains("(40.0%)"));
        assert!(out.ends_with("T0 = 2023-11-14T22:13:20Z"));
    }

    #[test]
    fn display_renders_dir_layout_label() {
        let mut s = fixture_summary();
        s.output_layout = Layout::Dir;
        let out = s.to_string();
        assert!(out.contains("oci layout dir"));
        assert!(!out.contains("oci layout tar"));
    }

    #[test]
    fn display_includes_t0_in_rfc3339() {
        let s = fixture_summary();
        let out = s.to_string();
        // T0 = 1_700_000_000 unix = 2023-11-14T22:13:20Z (matches the
        // timestamp module's known-value test).
        assert!(out.contains("T0 = 2023-11-14T22:13:20Z"));
    }

    #[test]
    fn display_vs_naive_column_factor() {
        let s = fixture_summary();
        let out = s.to_string();
        // Shared {0,1}: |M|=2, size=1_000_000 -> +1_000_000
        assert!(out.contains("+1000000"));
        // Per-image rows show the em-dash.
        assert!(out.contains("—"));
    }

    #[test]
    fn display_includes_truncated_diff_id_for_each_layer() {
        let s = fixture_summary();
        let out = s.to_string();
        assert!(out.contains("sha256:aaaaaaaaaaaa…"));
        assert!(out.contains("sha256:111122223333…"));
        assert!(out.contains("sha256:eeeeffffaaaa…"));
    }

    #[test]
    fn empty_run_is_well_formed() {
        // Defensive check: a run with no inputs / no layers still
        // renders something readable rather than panicking.
        let s = Summary {
            inputs: Vec::new(),
            output_path: PathBuf::from("/tmp/empty.tar"),
            output_layout: Layout::Tar,
            layers: Vec::new(),
            image_manifests: Vec::new(),
            t0: T0::from_unix_seconds(0),
        };
        let out = s.to_string();
        assert!(out.contains("layermeld run summary"));
        assert!(out.contains("T0 = 1970-01-01T00:00:00Z"));
        assert!(out.contains("inputs total (squashed):      0"));
        assert!(out.contains("outputs total (deduplicated): 0"));
        assert!(out.contains("saved:                        0"));
        assert!(out.contains("(0.0%)"));
    }

    #[test]
    fn untagged_label_renders_verbatim() {
        // Caller is responsible for passing whatever label they want
        // (e.g. "<untagged>"); the formatter does not re-derive.
        let mut s = fixture_summary();
        s.inputs[1].label = "<untagged>".into();
        s.image_manifests[1].label = "<untagged>".into();
        let out = s.to_string();
        assert!(out.contains("<untagged>"));
    }

    #[test]
    fn membership_label_does_not_panic_on_arbitrary_ids() {
        // Large image-id values must not blow up the renderer.
        let m = ImageSet::from_ids([InputImageId(usize::MAX)]);
        let label = membership_label(&m);
        assert!(label.starts_with("per-image {"));
        assert!(label.contains(&usize::MAX.to_string()));
    }
}
