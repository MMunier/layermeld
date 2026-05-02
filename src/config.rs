//! Typed configuration consumed by [`crate::run`].
//!
//! `main.rs` is the only place that builds a [`Config`] from argv;
//! library tests construct it directly. See spec 10 for the source CLI
//! and spec 11 §11.3 for the canonicalize-and-dedupe rule on input paths.

use std::path::PathBuf;

use crate::cli::{Cli, Layout};
use crate::error::{Error, Result};

/// Resolved run configuration.
///
/// Mirrors [`Cli`] field-for-field, with one transformation applied at
/// construction time: `inputs` are canonicalised to absolute paths,
/// duplicates are collapsed (spec 11 §11.3 — "two different paths that
/// happen to resolve to the same inode are also collapsed"), and the
/// resulting list is sorted lexicographically. Downstream code can
/// therefore treat `inputs[i]` as the canonical path for `image_id == i`,
/// with no further sort or dedupe needed.
///
/// Construction is the only place that touches the filesystem on the
/// argv-to-config path. [`Config::from_cli`] surfaces a missing /
/// unreadable input path as [`Error::Io`] (exit code 1 per spec 10
/// §10.7) — argv-shape errors come out of clap before this point and
/// get exit code 2.
#[derive(Debug, Clone)]
pub struct Config {
    /// Input image paths, canonicalised + deduped + lex-sorted. Their
    /// position in this vector is the [`InputImageId`] downstream stages
    /// use as a slice index.
    ///
    /// [`InputImageId`]: crate::squash::index::InputImageId
    pub inputs: Vec<PathBuf>,

    /// Output destination (spec 10 §10.3). Not canonicalised — it does
    /// not exist yet.
    pub output: PathBuf,

    /// Output packaging shape (spec 09 §9.3).
    pub layout: Layout,

    /// Minimum estimated tar size for a shared subset layer to survive
    /// the dissolve pass (spec 05 §5.5).
    pub min_layer_size: u64,

    /// Move an existing destination aside instead of failing (spec 09
    /// §9.4).
    pub force: bool,

    /// Pinned `T0` in Unix seconds, if `--timestamp` was given (spec 06
    /// §6.1). `None` defers to `SOURCE_DATE_EPOCH` / wall clock.
    pub timestamp: Option<i64>,

    /// Bound on concurrent layer assembly tasks (spec 07 §7.5). `0`
    /// lets `rayon` pick the logical CPU count.
    pub jobs: usize,

    /// Scratch directory override. `None` falls back to the default
    /// `<output>.partial/` (spec 10 §10.4). Not canonicalised — the
    /// path may not exist yet.
    pub scratch: Option<PathBuf>,

    /// Verbosity counter (`-v` / `-vv` / ...).
    pub verbose: u8,

    /// Suppress the run summary on stdout (spec 10 §10.6).
    pub quiet: bool,

    /// Skip the final blob/index/oci-layout writes (spec 10 §10.4).
    pub dry_run: bool,
}

impl Config {
    /// Build a [`Config`] from parsed argv.
    ///
    /// Performs the spec 11 §11.3 normalisation on input paths:
    /// 1. Canonicalise each path via [`std::fs::canonicalize`] (resolves
    ///    symlinks, makes the path absolute).
    /// 2. Collapse duplicate canonical paths silently — the same
    ///    physical input given twice (or via two different routes) is
    ///    counted once.
    /// 3. Sort the surviving canonical paths lexicographically so
    ///    `image_id` is a stable function of the input *set*, not of
    ///    argv order.
    ///
    /// All other fields are copied verbatim from [`Cli`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when canonicalisation of any input path
    /// fails (typically: path does not exist or is unreadable). Surfaces
    /// as exit code 1 per spec 10 §10.7 — argv-shape errors are handled
    /// by clap before this function is reached.
    pub fn from_cli(cli: Cli) -> Result<Self> {
        let inputs = canonicalize_and_dedupe(&cli.inputs)?;
        Ok(Self {
            inputs,
            output: cli.output,
            layout: cli.layout,
            min_layer_size: cli.min_layer_size,
            force: cli.force,
            timestamp: cli.timestamp,
            jobs: cli.jobs,
            scratch: cli.scratch,
            verbose: cli.verbose,
            quiet: cli.quiet,
            dry_run: cli.dry_run,
        })
    }
}

/// Canonicalise, dedupe, and lex-sort `paths`.
///
/// Pulled out of [`Config::from_cli`] so unit tests can exercise the
/// transformation without rebuilding a full [`Cli`] each time.
fn canonicalize_and_dedupe(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut canonical: Vec<PathBuf> = paths
        .iter()
        .map(|p| {
            std::fs::canonicalize(p).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("canonicalize input {}: {e}", p.display()),
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;

    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// Create three input files inside a fresh temp dir and return
    /// `(tempdir, [path_a, path_b, path_c])` with canonicalised paths.
    fn three_inputs() -> (TempDir, [PathBuf; 3]) {
        let td = TempDir::new().unwrap();
        let a = td.path().join("a.tar");
        let b = td.path().join("b.tar");
        let c = td.path().join("c.tar");
        for p in [&a, &b, &c] {
            fs::write(p, b"placeholder").unwrap();
        }
        let canon = [
            fs::canonicalize(&a).unwrap(),
            fs::canonicalize(&b).unwrap(),
            fs::canonicalize(&c).unwrap(),
        ];
        (td, canon)
    }

    #[test]
    fn canonicalize_makes_paths_absolute() {
        let td = TempDir::new().unwrap();
        let rel = td.path().join("img.tar");
        fs::write(&rel, b"x").unwrap();
        let result = canonicalize_and_dedupe(std::slice::from_ref(&rel)).unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].is_absolute(), "canonicalised path must be absolute");
    }

    #[test]
    fn dedupes_identical_paths() {
        let (_td, [a, _b, _c]) = three_inputs();
        // Same path given three times collapses to one.
        let out = canonicalize_and_dedupe(&[a.clone(), a.clone(), a.clone()]).unwrap();
        assert_eq!(out, vec![a]);
    }

    #[test]
    fn lex_sorts_canonical_paths() {
        let (_td, [a, b, c]) = three_inputs();
        // argv order c, a, b → output sorted a, b, c.
        let out = canonicalize_and_dedupe(&[c.clone(), a.clone(), b.clone()]).unwrap();
        assert_eq!(out, vec![a, b, c]);
    }

    #[test]
    fn argv_order_invariance() {
        // Spec 11 §11.3: "two invocations with the same set of input
        // paths in different argv orders therefore produce identical
        // output." The image_id assignment is a pure function of the
        // *set*, not of the order.
        let (_td, [a, b, c]) = three_inputs();
        let permutations = [
            [a.clone(), b.clone(), c.clone()],
            [a.clone(), c.clone(), b.clone()],
            [b.clone(), a.clone(), c.clone()],
            [b.clone(), c.clone(), a.clone()],
            [c.clone(), a.clone(), b.clone()],
            [c.clone(), b.clone(), a.clone()],
        ];
        let expected = canonicalize_and_dedupe(&permutations[0]).unwrap();
        for perm in &permutations[1..] {
            let out = canonicalize_and_dedupe(perm).unwrap();
            assert_eq!(out, expected, "permutation {perm:?} produced different output");
        }
    }

    #[cfg(unix)]
    #[test]
    fn collapses_symlink_to_same_target() {
        // Spec 11 §11.3: "two different paths that happen to resolve to
        // the same inode are collapsed via canonicalized-path comparison."
        let td = TempDir::new().unwrap();
        let real = td.path().join("real.tar");
        fs::write(&real, b"x").unwrap();
        let link = td.path().join("link.tar");
        symlink(&real, &link).unwrap();

        let out = canonicalize_and_dedupe(&[real.clone(), link.clone()]).unwrap();
        assert_eq!(out.len(), 1, "symlink and target should collapse");
        assert_eq!(out[0], fs::canonicalize(&real).unwrap());
    }

    #[test]
    fn missing_input_surfaces_as_io_error() {
        let td = TempDir::new().unwrap();
        let bogus = td.path().join("does-not-exist.tar");
        let err = canonicalize_and_dedupe(&[bogus]).unwrap_err();
        match err {
            Error::Io(_) => {}
            other => panic!("expected Error::Io, got {other:?}"),
        }
        // Sanity: this maps to exit code 1, not the argv-only exit 2.
        let err = canonicalize_and_dedupe(&[PathBuf::from("/nonexistent-/-/-")]).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn empty_input_list_is_ok() {
        // The clap layer already enforces `required = true, num_args =
        // 1..` on `<INPUT>...`, so we never see an empty list in
        // production — but the helper itself should still handle it
        // cleanly (e.g. for tests).
        let out = canonicalize_and_dedupe(&[]).unwrap();
        assert!(out.is_empty());
    }

    /// Build a populated [`Cli`] for the integration-shaped tests below.
    fn cli_with(inputs: Vec<PathBuf>, output: PathBuf) -> Cli {
        Cli {
            inputs,
            output,
            layout: Layout::Tar,
            min_layer_size: 16 * 1024,
            force: false,
            timestamp: Some(1_700_000_000),
            jobs: 0,
            scratch: None,
            verbose: 0,
            quiet: false,
            dry_run: false,
        }
    }

    #[test]
    fn from_cli_propagates_non_input_fields() {
        let (_td, [a, _b, _c]) = three_inputs();
        let mut cli = cli_with(vec![a.clone()], PathBuf::from("/tmp/out.tar"));
        cli.layout = Layout::Dir;
        cli.min_layer_size = 4096;
        cli.force = true;
        cli.timestamp = Some(-1);
        cli.jobs = 4;
        cli.scratch = Some(PathBuf::from("/tmp/scratch"));
        cli.verbose = 2;
        cli.quiet = false;
        cli.dry_run = true;

        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.inputs, vec![a]);
        assert_eq!(cfg.output, PathBuf::from("/tmp/out.tar"));
        assert_eq!(cfg.layout, Layout::Dir);
        assert_eq!(cfg.min_layer_size, 4096);
        assert!(cfg.force);
        assert_eq!(cfg.timestamp, Some(-1));
        assert_eq!(cfg.jobs, 4);
        assert_eq!(cfg.scratch, Some(PathBuf::from("/tmp/scratch")));
        assert_eq!(cfg.verbose, 2);
        assert!(!cfg.quiet);
        assert!(cfg.dry_run);
    }

    #[test]
    fn from_cli_canonicalises_and_dedupes_inputs() {
        let (_td, [a, b, c]) = three_inputs();
        // argv order: c, a, a, b → canonical sorted dedupe: a, b, c.
        let cli = cli_with(
            vec![c.clone(), a.clone(), a.clone(), b.clone()],
            PathBuf::from("/tmp/out.tar"),
        );
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.inputs, vec![a, b, c]);
    }

    #[test]
    fn from_cli_does_not_canonicalise_output() {
        // Output destination is allowed to not exist (it's about to be
        // created). Canonicalising it would fail; we must not.
        let (_td, [a, _b, _c]) = three_inputs();
        let nonexistent_output = PathBuf::from("/tmp/this-output-does-not-exist-yet.tar");
        let cli = cli_with(vec![a], nonexistent_output.clone());
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.output, nonexistent_output);
    }

    #[test]
    fn from_cli_does_not_canonicalise_scratch() {
        // Scratch dir is created on demand; canonicalising it would
        // fail when the user passes a not-yet-existing path.
        let (_td, [a, _b, _c]) = three_inputs();
        let nonexistent_scratch = PathBuf::from("/tmp/scratch-not-yet");
        let mut cli = cli_with(vec![a], PathBuf::from("/tmp/out.tar"));
        cli.scratch = Some(nonexistent_scratch.clone());
        let cfg = Config::from_cli(cli).unwrap();
        assert_eq!(cfg.scratch, Some(nonexistent_scratch));
    }

    #[test]
    fn from_cli_missing_input_propagates_io_error() {
        let cli = cli_with(
            vec![PathBuf::from("/this/path/should/not/exist")],
            PathBuf::from("/tmp/out.tar"),
        );
        let err = Config::from_cli(cli).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn from_cli_partial_failure_returns_first_error() {
        // If only one of N inputs is missing, we still surface an error
        // — we never silently drop a path the user named.
        let (_td, [a, _b, _c]) = three_inputs();
        let cli = cli_with(
            vec![a, PathBuf::from("/this/path/should/not/exist")],
            PathBuf::from("/tmp/out.tar"),
        );
        let err = Config::from_cli(cli).unwrap_err();
        match err {
            Error::Io(_) => {}
            other => panic!("expected Error::Io, got {other:?}"),
        }
    }
}
