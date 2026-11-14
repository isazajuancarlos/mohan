// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán.
//
// Oráculo AEAD — diferencial byte-a-byte de una implementación "roll-your-own" de
// ChaCha20-Poly1305 / AES-256-GCM contra el crate auditado de RustCrypto. El
// Poly1305 (aritmética mod 2^130-5) y el GHASH (mult en GF(2^128)) a mano casi
// siempre divergen en algún BORDE: largo 0, largo exacto de bloque (16/64), el
// relleno a 16 B del MAC, o la codificación de longitudes. Una divergencia del
// ciphertext‖tag es un fallo de interop/correctitud; un `open` que acepta un tag
// volteado es una FORJA.

use crate::{Clase, Divergencia, Informe};

/// Largos de mensaje que estresan los bordes de bloque (ChaCha=64, Poly/GHASH=16).
const LARGOS_MSG: &[usize] = &[0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 129, 255, 256, 511, 1000];
/// Largos de AAD (el relleno independiente del AAD en el MAC es un borde clásico).
const LARGOS_AAD: &[usize] = &[0, 1, 15, 16, 17, 64];

/// Caso AEAD determinista: clave, nonce, aad y mensaje de largos de borde.
#[derive(Clone, Debug)]
pub struct CasoAead {
    pub clave: [u8; 32],
    pub nonce: [u8; 12],
    pub aad: Vec<u8>,
    pub mensaje: Vec<u8>,
}

impl CasoAead {
    #[must_use]
    pub fn lote(n: u32) -> Vec<CasoAead> {
        (0..n)
            .map(|i| {
                let iu = i as usize;
                let lm = LARGOS_MSG[iu % LARGOS_MSG.len()];
                let la = LARGOS_AAD[(iu / LARGOS_MSG.len()) % LARGOS_AAD.len()];
                let mut clave = [0u8; 32];
                let mut nonce = [0u8; 12];
                for (j, b) in clave.iter_mut().enumerate() {
                    *b = (i.wrapping_mul(2_654_435_761).wrapping_add(j as u32) >> 3) as u8;
                }
                for (j, b) in nonce.iter_mut().enumerate() {
                    *b = (i.wrapping_add(0x9E37_79B9).wrapping_add(j as u32)) as u8;
                }
                let mensaje = (0..lm).map(|k| (k as u32).wrapping_mul(31).wrapping_add(i) as u8).collect();
                let aad = (0..la).map(|k| (k as u32).wrapping_mul(17).wrapping_add(i ^ 0x5A) as u8).collect();
                CasoAead { clave, nonce, aad, mensaje }
            })
            .collect()
    }
}

/// Un AEAD adaptado sobre bytes (salida `ciphertext‖tag`).
pub trait AdaptadorAead {
    fn nombre(&self) -> &str;
    fn seal(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, String>;
}

// ── Referencias auditadas (RustCrypto) ──────────────────────────────────────

/// Referencia ChaCha20-Poly1305 (RFC 8439) del crate `chacha20poly1305`.
pub struct RefChaChaPoly;

impl AdaptadorAead for RefChaChaPoly {
    fn nombre(&self) -> &str {
        "ref/chacha20poly1305"
    }
    fn seal(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
        let c = ChaCha20Poly1305::new(clave.into());
        c.encrypt(nonce.into(), Payload { msg, aad }).map_err(|e| e.to_string())
    }
    fn open(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
        let c = ChaCha20Poly1305::new(clave.into());
        c.decrypt(nonce.into(), Payload { msg: ct_tag, aad }).map_err(|e| e.to_string())
    }
}

/// Referencia AES-256-GCM del crate `aes-gcm`.
pub struct RefAesGcm;

impl AdaptadorAead for RefAesGcm {
    fn nombre(&self) -> &str {
        "ref/aes-256-gcm"
    }
    fn seal(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit};
        let c = Aes256Gcm::new(clave.into());
        c.encrypt(nonce.into(), Payload { msg, aad }).map_err(|e| e.to_string())
    }
    fn open(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, String> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit};
        let c = Aes256Gcm::new(clave.into());
        c.decrypt(nonce.into(), Payload { msg: ct_tag, aad }).map_err(|e| e.to_string())
    }
}

// ── Objetivo: easylock (roll-your-own) ──────────────────────────────────────

/// OBJETIVO AEAD 1a: el ChaCha20-Poly1305 PROPIO de easylock.
pub struct EasylockChaChaPoly;

impl AdaptadorAead for EasylockChaChaPoly {
    fn nombre(&self) -> &str {
        "easylock/chacha20poly1305@b662da2"
    }
    fn seal(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        use easylock_core::aead::Aead;
        let c = easylock_core::aead::ChaCha20Poly1305::new(clave).map_err(|e| format!("{e:?}"))?;
        Ok(c.seal(nonce, aad, msg))
    }
    fn open(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, String> {
        use easylock_core::aead::Aead;
        let c = easylock_core::aead::ChaCha20Poly1305::new(clave).map_err(|e| format!("{e:?}"))?;
        c.open(nonce, aad, ct_tag).map_err(|e| format!("{e:?}"))
    }
}

/// OBJETIVO AEAD 1b: el AES-256-GCM PROPIO de easylock (GHASH a mano).
pub struct EasylockAesGcm;

impl AdaptadorAead for EasylockAesGcm {
    fn nombre(&self) -> &str {
        "easylock/aes-256-gcm@b662da2"
    }
    fn seal(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
        use easylock_core::aead::Aead;
        let c = easylock_core::aead::Aes256Gcm::new(clave).map_err(|e| format!("{e:?}"))?;
        Ok(c.seal(nonce, aad, msg))
    }
    fn open(&self, clave: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, String> {
        use easylock_core::aead::Aead;
        let c = easylock_core::aead::Aes256Gcm::new(clave).map_err(|e| format!("{e:?}"))?;
        c.open(nonce, aad, ct_tag).map_err(|e| format!("{e:?}"))
    }
}

/// Oráculo DIFERENCIAL AEAD: exige `ciphertext‖tag` idéntico byte-a-byte a la
/// referencia, round-trip del objetivo, e `open` que RECHAZA un tag/ciphertext
/// volteado (si acepta → forja).
///
/// # Errors
/// Nunca: una divergencia es un hallazgo (va en el Informe), no un error; los
/// fallos de `seal` de la referencia se registran como divergencia.
pub fn diferencial_aead(
    referencia: &dyn AdaptadorAead,
    objetivo: &dyn AdaptadorAead,
    casos: &[CasoAead],
) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    for (i, c) in casos.iter().enumerate() {
        let i = i as u32;
        let s_ref = match referencia.seal(&c.clave, &c.nonce, &c.aad, &c.mensaje) {
            Ok(s) => s,
            Err(e) => {
                inf.divergencias.push(Divergencia { caso: i, clase: Clase::RoundTrip, detalle: format!("ref.seal erró: {e}") });
                continue;
            }
        };
        let s_obj = match objetivo.seal(&c.clave, &c.nonce, &c.aad, &c.mensaje) {
            Ok(s) => s,
            Err(e) => {
                inf.divergencias.push(Divergencia { caso: i, clase: Clase::FirmaBytes, detalle: format!("objetivo.seal erró donde la ref no: {e}") });
                continue;
            }
        };

        if s_ref != s_obj {
            // localiza DÓNDE: ¿difiere el ciphertext o el tag (últimos 16 B)?
            let tl = 16usize;
            let detalle = if s_ref.len() != s_obj.len() {
                format!("largo distinto ref={} obj={} (msg={} aad={})", s_ref.len(), s_obj.len(), c.mensaje.len(), c.aad.len())
            } else {
                let ct_dif = s_ref[..s_ref.len() - tl] != s_obj[..s_obj.len() - tl];
                let tag_dif = s_ref[s_ref.len() - tl..] != s_obj[s_obj.len() - tl..];
                format!(
                    "{}{} difieren (msg={} aad={})",
                    if ct_dif { "CIPHERTEXT " } else { "" },
                    if tag_dif { "TAG" } else { "" },
                    c.mensaje.len(),
                    c.aad.len()
                )
            };
            inf.divergencias.push(Divergencia { caso: i, clase: Clase::FirmaBytes, detalle });
        }

        // round-trip del objetivo.
        match objetivo.open(&c.clave, &c.nonce, &c.aad, &s_obj) {
            Ok(m) if m == c.mensaje => {}
            Ok(_) => inf.divergencias.push(Divergencia { caso: i, clase: Clase::RoundTrip, detalle: "open(seal propio) no recupera el mensaje".into() }),
            Err(e) => inf.divergencias.push(Divergencia { caso: i, clase: Clase::RoundTrip, detalle: format!("open(seal propio) erró: {e}") }),
        }

        // forja: tag volteado DEBE ser rechazado.
        if !s_obj.is_empty() {
            let mut falso = s_obj.clone();
            let n = falso.len();
            falso[n - 1] ^= 0x01;
            if objetivo.open(&c.clave, &c.nonce, &c.aad, &falso).is_ok() {
                inf.divergencias.push(Divergencia { caso: i, clase: Clase::AceptaManipulada, detalle: "open ACEPTÓ un tag volteado (FORJA)".into() });
            }
        }
    }
    Ok(inf)
}

#[cfg(test)]
mod pruebas {
    use super::{diferencial_aead, AdaptadorAead, CasoAead, RefAesGcm, RefChaChaPoly};
    use crate::Clase;

    // Control positivo: la referencia contra sí misma, limpia (ChaCha y AES).
    #[test]
    fn ref_vs_ref_limpio() {
        let casos = CasoAead::lote(48);
        assert!(diferencial_aead(&RefChaChaPoly, &RefChaChaPoly, &casos).unwrap().limpio());
        assert!(diferencial_aead(&RefAesGcm, &RefAesGcm, &casos).unwrap().limpio());
    }

    // Control ROJO (D33): un AEAD cuyo seal corrompe un byte del tag DEBE salir como
    // FirmaBytes; y uno cuyo open acepta todo DEBE salir como AceptaManipulada.
    struct SealMutante;
    impl AdaptadorAead for SealMutante {
        fn nombre(&self) -> &str { "SEAL-MUTANTE(control)" }
        fn seal(&self, k: &[u8; 32], n: &[u8; 12], a: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
            let mut s = RefChaChaPoly.seal(k, n, a, m)?;
            if let Some(b) = s.last_mut() { *b ^= 0x01; }
            Ok(s)
        }
        fn open(&self, k: &[u8; 32], n: &[u8; 12], a: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
            RefChaChaPoly.open(k, n, a, c)
        }
    }

    #[test]
    fn caza_seal_mutante() {
        let casos = CasoAead::lote(8);
        let inf = diferencial_aead(&RefChaChaPoly, &SealMutante, &casos).unwrap();
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::FirmaBytes),
            "no cazó el seal mutante: {:?}",
            inf.divergencias
        );
    }

    struct AeadLaxo;
    impl AdaptadorAead for AeadLaxo {
        fn nombre(&self) -> &str { "AEAD-LAXO(control)" }
        fn seal(&self, k: &[u8; 32], n: &[u8; 12], a: &[u8], m: &[u8]) -> Result<Vec<u8>, String> {
            RefChaChaPoly.seal(k, n, a, m)
        }
        // acepta cualquier cosa quitando el tag: forja.
        fn open(&self, _k: &[u8; 32], _n: &[u8; 12], _a: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
            Ok(c[..c.len().saturating_sub(16)].to_vec())
        }
    }

    #[test]
    fn caza_open_laxo() {
        let casos = CasoAead::lote(8);
        let inf = diferencial_aead(&RefChaChaPoly, &AeadLaxo, &casos).unwrap();
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::AceptaManipulada),
            "no cazó el open laxo (forja): {:?}",
            inf.divergencias
        );
    }
}
