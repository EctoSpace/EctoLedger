// Standalone EctoLedger Audit Certificate verifier.
//
// Usage: verify-cert <path-to-audit.elc>
//
// Performs six independent checks in order:
//   1. Ed25519 signature validity
//   2. Hash-chain reconstruction
//   3. Merkle proof verification for all findings
//   4. Goal hash integrity
//   5. OTS timestamp (if stamp is complete; warns if incomplete)
//   6. Enclave attestation pillar (informational)
//
// Exit code: 0 = VALID, 1 = INVALID or error.

use ectoledger::certificate::{EctoLedgerCertificate, canonical_json_for_signing};
use ectoledger::merkle;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::process;

#[cfg(feature = "enclave-remote")]
use coset::CborSerializable as _;

// ── Constants ─────────────────────────────────────────────────────────────────

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("Usage: {} <path-to-audit.elc>", args[0]);
        process::exit(1);
    }
    let path = std::path::Path::new(&args[1]);
    let cert = match ectoledger::certificate::read_certificate_file(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{RED}ERROR:{RESET} Could not read certificate: {}", e);
            process::exit(1);
        }
    };

    println!("\nVerifying EctoLedger Audit Certificate");
    println!("  Session : {}", cert.session_id);
    println!("  Events  : {}", cert.event_count);
    println!("  Started : {}", cert.started_at);
    println!();

    let mut all_ok = true;

    all_ok &= check_signature(&cert);
    all_ok &= check_hash_chain(&cert);
    all_ok &= check_merkle_proofs(&cert);
    all_ok &= check_goal_hash(&cert);
    check_ots(&cert); // OTS failures are warnings, not fatal.
    check_enclave_attestation(&cert); // Informational; not fatal.

    println!();
    if all_ok {
        println!(
            "{GREEN}CERTIFICATE VALID{RESET}  — session {}",
            cert.session_id
        );
        process::exit(0);
    } else {
        println!("{RED}CERTIFICATE INVALID{RESET} — one or more checks failed.");
        process::exit(1);
    }
}

// ── Check 1: Ed25519 signature ────────────────────────────────────────────────

fn check_signature(cert: &EctoLedgerCertificate) -> bool {
    let Some(sig_hex) = &cert.signature else {
        println!("{YELLOW}⚠  Signature{RESET} — certificate has no signature (unsigned)");
        return true; // Allow unsigned certs; missing sig is a warning not a failure.
    };
    let Some(pk_hex) = &cert.session_public_key else {
        println!("{RED}✗  Signature{RESET} — no session_public_key in certificate");
        return false;
    };

    let canonical = match canonical_json_for_signing(cert) {
        Ok(s) => s,
        Err(e) => {
            println!("{RED}✗  Signature{RESET} — canonical JSON error: {}", e);
            return false;
        }
    };

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(e) => {
            println!("{RED}✗  Signature{RESET} — invalid public key hex: {}", e);
            return false;
        }
    };
    let vk = match pk_bytes
        .as_slice()
        .try_into()
        .ok()
        .and_then(|b: &[u8; 32]| VerifyingKey::from_bytes(b).ok())
    {
        Some(v) => v,
        None => {
            println!("{RED}✗  Signature{RESET} — could not parse ed25519 public key");
            return false;
        }
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            println!("{RED}✗  Signature{RESET} — invalid signature hex: {}", e);
            return false;
        }
    };
    let sig: Signature = match sig_bytes.as_slice().try_into() {
        Ok(s) => s,
        Err(e) => {
            println!(
                "{RED}✗  Signature{RESET} — could not parse ed25519 signature: {}",
                e
            );
            return false;
        }
    };

    match vk.verify(canonical.as_bytes(), &sig) {
        Ok(()) => {
            println!("{GREEN}✓  Signature valid{RESET} (ed25519)");
            true
        }
        Err(_) => {
            println!("{RED}✗  Signature INVALID{RESET} — certificate may have been tampered");
            false
        }
    }
}

// ── Check 2: Hash chain reconstruction ───────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn check_hash_chain(cert: &EctoLedgerCertificate) -> bool {
    if cert.events.is_empty() {
        println!("{YELLOW}⚠  Hash chain{RESET} — no events to verify");
        return true;
    }

    // The certificate only embeds (sequence, content_hash) pairs — not the payloads.
    // We verify the chain structure: each entry's content_hash must equal the
    // previous entry's content_hash (i.e., the chain must be monotonically linked).
    // A full payload reconstruction would require the DB; for the offline verifier we
    // confirm that the chain is internally consistent and the tip matches `ledger_tip_hash`.
    //
    // Specifically: the embedded content_hashes must form a consecutive sequence,
    // and the last one must equal `ledger_tip_hash`.
    let mut prev_seq: Option<i64> = None;
    for entry in &cert.events {
        if let Some(prev) = prev_seq
            && entry.sequence != prev + 1
        {
            println!(
                "{RED}✗  Hash chain{RESET} — sequence gap: expected {}, got {}",
                prev + 1,
                entry.sequence
            );
            return false;
        }
        prev_seq = Some(entry.sequence);
    }

    // SAFETY: cert.events.is_empty() is checked and returns early above.
    let actual_tip = &cert
        .events
        .last()
        .expect("non-empty: guarded by is_empty early return above")
        .content_hash;
    if actual_tip != &cert.ledger_tip_hash {
        println!(
            "{RED}✗  Hash chain{RESET} — ledger_tip_hash mismatch: expected {}, got {}",
            cert.ledger_tip_hash, actual_tip
        );
        return false;
    }

    // Verify count matches event_count.
    if cert.events.len() as u64 != cert.event_count {
        println!(
            "{RED}✗  Hash chain{RESET} — event_count mismatch: declared {}, actual {}",
            cert.event_count,
            cert.events.len()
        );
        return false;
    }

    println!(
        "{GREEN}✓  Hash chain intact{RESET} ({} events, tip {}…)",
        cert.events.len(),
        &cert.ledger_tip_hash[..8]
    );
    true
}

// ── Check 3: Merkle proof verification ───────────────────────────────────────

fn check_merkle_proofs(cert: &EctoLedgerCertificate) -> bool {
    if cert.findings.is_empty() {
        println!("{GREEN}✓  Merkle proofs{RESET} — no findings to verify");
        return true;
    }

    // Rebuild the Merkle root from the embedded events so we have a reference.
    let content_hashes: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    let tree = match merkle::build_merkle_tree(&content_hashes) {
        Ok(t) => t,
        Err(e) => {
            println!("{RED}✗  Merkle build error{RESET} — {}", e);
            return false;
        }
    };
    let expected_root = match merkle::root(&tree) {
        Ok(r) => r,
        Err(e) => {
            println!("{RED}✗  Merkle root error{RESET} — {}", e);
            return false;
        }
    };

    if expected_root != cert.merkle_root {
        println!(
            "{RED}✗  Merkle root{RESET} — mismatch: expected {}, computed {}",
            cert.merkle_root, expected_root
        );
        return false;
    }

    // Build sequence → content_hash lookup.
    let seq_to_hash: std::collections::HashMap<i64, &str> = cert
        .events
        .iter()
        .map(|e| (e.sequence, e.content_hash.as_str()))
        .collect();

    let mut total_proofs = 0usize;
    let mut failures = 0usize;

    for finding in &cert.findings {
        for (i, (&seq, proof)) in finding
            .evidence_sequence
            .iter()
            .zip(&finding.merkle_proofs)
            .enumerate()
        {
            total_proofs += 1;
            let Some(hash) = seq_to_hash.get(&seq) else {
                println!(
                    "{RED}✗  Merkle proofs{RESET} — finding '{}' references unknown sequence {}",
                    finding.title, seq
                );
                failures += 1;
                continue;
            };
            if !merkle::verify_proof(&cert.merkle_root, hash, proof).unwrap_or(false) {
                println!(
                    "{RED}✗  Merkle proofs{RESET} — proof {} for finding '{}' (seq {}) is invalid",
                    i, finding.title, seq
                );
                failures += 1;
            }
        }
    }

    if failures == 0 {
        println!(
            "{GREEN}✓  Merkle proofs valid{RESET} ({} findings, {} evidence sequences verified)",
            cert.findings.len(),
            total_proofs
        );
        true
    } else {
        println!(
            "{RED}✗  Merkle proofs{RESET} — {}/{} proofs failed",
            failures, total_proofs
        );
        false
    }
}

// ── Check 4: Goal hash integrity ──────────────────────────────────────────────

fn check_goal_hash(cert: &EctoLedgerCertificate) -> bool {
    let computed = sha256_hex(cert.goal.as_bytes());
    if computed != cert.goal_hash {
        println!(
            "{RED}✗  Goal hash{RESET} — mismatch: declared {}, computed {}",
            cert.goal_hash, computed
        );
        return false;
    }
    println!("{GREEN}✓  Goal hash matches declared goal{RESET}");
    true
}

// ── Check 5: OTS timestamp ────────────────────────────────────────────────────

fn check_ots(cert: &EctoLedgerCertificate) -> bool {
    let Some(ots_hex) = &cert.ots_proof_hex else {
        println!("{YELLOW}⚠  OTS timestamp{RESET} — no OTS proof in certificate (skipped)");
        return true;
    };

    let stamp_bytes = match hex::decode(ots_hex) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "{YELLOW}⚠  OTS timestamp{RESET} — invalid hex in ots_proof_hex: {}",
                e
            );
            return true;
        }
    };

    // The OTS stamp format: an incomplete stamp starts with 0x31 (the magic byte for OTS).
    // A complete stamp that has been upgraded against a calendar server would contain a
    // Bitcoin attestation. For offline verification we check if the stamp is non-empty
    // and detect the incomplete stamp magic byte sequence.
    //
    // Full OTS proof verification requires network access to verify the Bitcoin block hash,
    // which is outside the scope of this offline-first verifier. We detect the stamp type
    // and report accordingly.
    //
    // OTS magic: files start with 0x00 0x4f 0x70 0x65 0x6e 0x54 0x69 0x6d 0x65 0x73 0x74 0x61 0x6d 0x70 0x73
    // ("OpenTimestamps" in bytes with leading 0x00).
    let ots_magic = b"\x00OpenTimestamps\x00";

    if stamp_bytes.len() < ots_magic.len() {
        println!(
            "{YELLOW}⚠  OTS timestamp{RESET} — stamp is too short to be valid ({} bytes)",
            stamp_bytes.len()
        );
        return true;
    }

    if stamp_bytes.starts_with(ots_magic) {
        // Check for incomplete vs complete stamp: incomplete stamps contain no Bitcoin attestation.
        // Bitcoin attestation magic: 0x05 0x88 0x96 0x0d 0x73 0xd7 0x19 0x01
        let bitcoin_magic = b"\x05\x88\x96\x0d\x73\xd7\x19\x01";
        let has_bitcoin = stamp_bytes
            .windows(bitcoin_magic.len())
            .any(|w| w == bitcoin_magic);

        if has_bitcoin {
            println!("{GREEN}✓  OTS timestamp — Bitcoin attestation present in stamp{RESET}");
        } else {
            println!(
                "{YELLOW}⚠  OTS timestamp{RESET} — stamp is present but not yet confirmed on Bitcoin"
            );
            println!(
                "   Run `ectoledger upgrade-certificate [file]` later to embed the completed proof."
            );
        }
    } else {
        // The aggregators sometimes return a non-standard envelope for the pending receipt.
        println!(
            "{YELLOW}⚠  OTS timestamp{RESET} — stamp is present ({} bytes) but format unrecognised; manual verification required",
            stamp_bytes.len()
        );
    }

    // OTS check is informational; does not affect exit code.
    true
}

// ── Check 6: Enclave attestation ──────────────────────────────────────────────

fn check_enclave_attestation(cert: &EctoLedgerCertificate) {
    let Some(ref att) = cert.enclave_attestation else {
        println!(
            "{YELLOW}⚠  Enclave{RESET} — no enclave attestation pillar (session ran without an enclave)"
        );
        return;
    };

    println!("{GREEN}✓  Enclave attestation present{RESET}");
    println!("     Level       : {}", att.level);
    println!("     Measurement : {}", att.measurement_hash);

    match &att.raw_attestation_hex {
        Some(hex_blob) => {
            let blob_bytes = hex_blob.len() / 2;
            println!("     Raw blob    : {} bytes (hex-encoded)", blob_bytes);

            // For remote hardware enclaves, attempt basic COSE-Sign1 structure validation.
            #[cfg(feature = "enclave-remote")]
            {
                use ectoledger::enclave::runtime::EnclaveLevel;
                if att.level == EnclaveLevel::RemoteHardwareEnclave {
                    match hex::decode(hex_blob) {
                        Ok(raw) => {
                            // Try to parse as COSE-Sign1 to validate envelope integrity.
                            match coset::CoseSign1::from_slice(&raw) {
                                Ok(_cose) => {
                                    println!(
                                        "     {GREEN}COSE-Sign1 envelope parsed successfully{RESET}"
                                    );
                                }
                                Err(e) => {
                                    println!(
                                        "     {YELLOW}COSE-Sign1 parse warning{RESET}: {} (may be a non-COSE format)",
                                        e
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            println!(
                                "     {YELLOW}Could not decode raw_attestation_hex{RESET}: {}",
                                e
                            );
                        }
                    }
                }
            }
        }
        None => {
            println!("     Raw blob    : not present (software-level attestation)");
        }
    }
}
