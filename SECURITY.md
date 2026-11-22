# Security model and release requirements

SeedCrypt protects stored content against someone who obtains encrypted notes without their password. It authenticates content before displaying or exporting plaintext. It does not protect against a compromised operating system, an administrator, a keylogger, terminal recordings, or someone who knows the password. This project is not independently certified.

## Passwords and memory

New passwords must contain at least 16 Unicode characters and five distinct non-whitespace characters, fit within 1,024 UTF-8 bytes, and avoid the limited common/repeated patterns rejected by the application. This policy is a floor, not an entropy guarantee or a comprehensive breached-password check. Use a unique randomly generated passphrase. Existing notes can still be decrypted with their original passwords, including passwords that do not meet the new policy.

The release profile uses unwinding. Guarded secrets, temporary outputs, terminal state and loading workers are cleaned up on ordinary errors and recoverable panics. The panic hook avoids printing panic payloads. Forced termination, out-of-memory aborts, power failure, cleanup errors, operating-system copies and swap can bypass cleanup. Memory is not locked against paging.

## Atomic output

Output is staged in a randomly named file in the destination directory, flushed, and published without overwriting an existing destination. A normal error or unwind before publication triggers best-effort removal of the staging file. On Windows, publication renames the open handle while ancestor directories remain pinned; the committed file is flushed again. On Unix, publication links relative to the pinned directory, synchronizes the directory, removes the staging name and synchronizes again. Newly created directory entries are also synchronized on Unix.

A synchronization error after publication can leave a complete final file even though the operation reports an error. Inspect the output before retrying; the application will not overwrite it. Unsupported filesystem operations fail instead of falling back to a non-atomic overwrite. The guarantees depend on filesystem and hardware behavior. Crash/power-loss testing on each supported deployment filesystem remains a release requirement. Staging files left by a crash may contain plaintext during export; removal is not secure disk erasure.

Use private, trusted folders with suitable filesystem permissions. Windows files inherit folder ACLs. Unix output files are created with mode 0600 and new directories with mode 0700. Do not run the application with elevated privileges or inside attacker-writable directory trees. Source files must not be modified concurrently if a consistent backup snapshot is required.

## Batch integrity

New batches bind each member to a random batch ID and an index inside authenticated encryption. An encrypted `batch_manifest.json` records the expected opaque filenames, ciphertext SHA-256 hashes, count, and completion state. Batch decryption verifies the manifest and all expected members before exporting any file; each member is checked again immediately before decryption/export. Missing, substituted, reordered or modified expected members cause an error. Additional unlisted JSON files are ignored and counted as skipped.

Cancelled or failed batches are marked incomplete. A crash before manifest commit leaves bound members that cannot masquerade as a complete legacy batch. Menu 8 allows individual recovery, with an explicit warning that collection completeness is not verified. Batch members cannot be individually password-rotated in menu 6; recover and create a new batch instead. Batch encryption requires a new or empty output directory.

Legacy folders without a manifest require explicit consent to proceed without completeness guarantees. That opt-in never permits bound new-format members to be treated as legacy. Replacing an entire batch, including its valid manifest, with an older valid batch cannot be detected without a trusted external record; rollback protection and remote backup inventory are not provided.

## Validation and release gates

The regression suite includes legacy compatibility, authenticated metadata, batch completeness and substitution, password policy, filename spoofing controls, link/junction rejection, concurrent no-overwrite publication, injected writer errors, and panic cleanup. The GitHub workflow runs formatting, Clippy, release tests and release builds on Windows and Linux, and a RustSec advisory check. Workflow actions are pinned and the workflow token has read-only repository permissions.

Local Windows results and Unix/Android cross-compilation do not establish Unix runtime correctness. Before distributing a release, require successful native CI results and test real disk exhaustion, permission changes, interruption, and crash/power-loss recovery on the intended filesystems. CI does not publish or sign release artifacts. Distribution signatures, provenance, private vulnerability handling, and independent review remain release-owner responsibilities.

Report suspected vulnerabilities privately to the repository owner through an available private channel. Do not include real passwords, seed phrases, private files, or production ciphertext in public issues.
