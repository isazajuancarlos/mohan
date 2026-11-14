// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán — OBJETIVO 5 (QRL/Zond), HILO 3.
//
// Diferencial de 3 vías ML-DSA-87: fips204 (referencia) ↔ rust-qrllib (nativo) ↔
// go-qrllib (CLI, en `qrl_go`). QRL usa ML-DSA-87 from-scratch en DOS impl del MISMO
// equipo (go y rust), probadas cada una contra KATs pero NO una contra otra en inputs
// ADVERSARIOS. Una divergencia accept/reject en verify = consensus/interop split.
//
// Firma en modo DETERMINISTA (rnd = 32 ceros, FIPS 204 §3.4) en las dos puntas, para
// que el diferencial de bytes de keygen/firma sea significativo (go-qrllib quitó el
// modo determinista en TOB-QRLLIB-6, así que a go solo se le aplica el diff de VERIFY).

use crate::AdaptadorMlDsa;
use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use qrllib::mldsa::{self, MlDsa87, PublicKey};
use std::path::PathBuf;
use std::process::Command;

fn a_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn de_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex impar ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Referencia FIPS 204 a nivel ML-DSA-87 (el nivel de QRL). Firma determinista
/// (rnd = 0) para casar byte-a-byte con el modo determinista de QRL.
pub struct Fips204_87;

impl AdaptadorMlDsa for Fips204_87 {
    fn nombre(&self) -> &str {
        "fips204/ml-dsa-87"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (pk, sk) = ml_dsa_87::KG::keygen_from_seed(semilla);
        Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        _semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let arr: [u8; ml_dsa_87::SK_LEN] = sk
            .try_into()
            .map_err(|_| format!("sk con largo {} != {}", sk.len(), ml_dsa_87::SK_LEN))?;
        let sk = ml_dsa_87::PrivateKey::try_from_bytes(arr).map_err(|e| e.to_string())?;
        // rnd = 0 → modo determinista FIPS 204, para casar con QRL deterministic.
        let sig = sk
            .try_sign_with_seed(&[0u8; 32], msg, ctx)
            .map_err(|e| e.to_string())?;
        Ok(sig.to_vec())
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let Ok(pk_arr): Result<[u8; ml_dsa_87::PK_LEN], _> = pk.try_into() else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; ml_dsa_87::SIG_LEN], _> = sig.try_into() else {
            return false;
        };
        let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk_arr) else {
            return false;
        };
        pk.verify(msg, &sig_arr, ctx)
    }
}

/// Adaptador NATIVO de `theQRL/rust-qrllib` (crate `qrllib`). ML-DSA-87 from-scratch,
/// ToB-auditado. Firma determinista (rnd = 0). `keygen`/`verify` corren la validación
/// de clave débil (igual que el nodo), por eso `verificar` devuelve false ante clave
/// débil o tamaño malo — el mismo veredicto que `ZondSigner.Sender`.
pub struct QrlRust87;

impl AdaptadorMlDsa for QrlRust87 {
    fn nombre(&self) -> &str {
        "rust-qrllib/ml-dsa-87"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let w = MlDsa87::from_seed(*semilla).map_err(|e| e.to_string())?;
        Ok((w.public_key_bytes().to_vec(), w.secret_key_bytes().to_vec()))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        _semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        mldsa::sign_with_secret_key_deterministic(ctx, msg, sk)
            .map(|a| a.to_vec())
            .map_err(|e| e.to_string())
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let Ok(pk) = PublicKey::from_bytes(pk) else {
            return false;
        };
        mldsa::verify_bytes(ctx, msg, sig, &pk).unwrap_or(false)
    }
}

/// Ruta del CLI puente a go-qrllib (la impl que corre en el nodo Zond), resuelta
/// relativa al manifiesto para no depender del cwd.
fn go_cli() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("objetivos/qrl/go-cli/mohan-qrl-cli")
}

fn correr_go(args: &[&str]) -> Result<String, String> {
    let out = Command::new(go_cli())
        .args(args)
        .output()
        .map_err(|e| format!("no se pudo lanzar el CLI go: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "CLI go salió {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Adaptador de `theQRL/go-qrllib` vía CLI — la impl ML-DSA-87 que corre en el
/// NODO Zond (consenso). Un go↔fips204 o go↔rust divergente es un consensus split.
/// El "sk" que devuelve `keygen` es el SEED de 32 B (handle), porque go no expone
/// carga-desde-SK; `firmar` re-deriva desde el seed y firma DETERMINISTA (rnd=0).
pub struct QrlGo87;

impl AdaptadorMlDsa for QrlGo87 {
    fn nombre(&self) -> &str {
        "go-qrllib/ml-dsa-87(CLI,nodo)"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let out = correr_go(&["keygen", &a_hex(semilla)])?;
        let mut it = out.split_whitespace();
        let pk = de_hex(it.next().ok_or("falta pk")?)?;
        let sk_handle = de_hex(it.next().ok_or("falta seed")?)?; // = el seed
        Ok((pk, sk_handle))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        _semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        // `sk` es el seed-handle de 32 B que devolvió keygen.
        let sig = correr_go(&["signdet", &a_hex(sk), &a_hex(ctx), &a_hex(msg)])?;
        de_hex(&sig)
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        matches!(
            correr_go(&["verify", &a_hex(pk), &a_hex(ctx), &a_hex(msg), &a_hex(sig)]),
            Ok(s) if s == "1"
        )
    }
}
