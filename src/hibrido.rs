// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán.
//
// Oráculo v2 — combinadores HÍBRIDOS (clásico + PQ, p. ej. X25519 + ML-KEM-768). El
// primitivo maduro salió seco; el bug de la ola 2026 vive en el PEGADO. La propiedad
// joya es el BINDING: el secreto derivado debe depender de TODOS los componentes del
// ciphertext (el ct ML-KEM y el ct clásico). Si manipular un componente NO cambia el
// secreto, ese componente no está ligado → non-binding, vía a downgrade / ataque por
// componente. Es single-impl y no necesita una segunda implementación.

use crate::kem::SemillaRng;
use crate::{Clase, Divergencia, Informe};

/// Caso determinista híbrido: semilla de clave (32 B) y semilla de encaps (64 B: los
/// combinadores X25519+ML-KEM toman 32 B para el mensaje ML-KEM y 32 B para la
/// efímera X25519).
#[derive(Clone, Debug)]
pub struct CasoHibrido {
    pub semilla_clave: [u8; 32],
    pub semilla_encaps: [u8; 64],
}

impl CasoHibrido {
    #[must_use]
    pub fn lote(n: u32) -> Vec<CasoHibrido> {
        (0..n)
            .map(|i| {
                let mut sc = [0u8; 32];
                sc[..4].copy_from_slice(&i.to_le_bytes());
                sc[31] = 0x7B;
                let mut se = [0u8; 64];
                se[..4].copy_from_slice(&i.wrapping_add(0x9E37_79B9).to_le_bytes());
                se[32..36].copy_from_slice(&i.wrapping_add(0x85EB_CA6B).to_le_bytes());
                se[31] = 0x1D;
                se[63] = 0xE1;
                CasoHibrido {
                    semilla_clave: sc,
                    semilla_encaps: se,
                }
            })
            .collect()
    }
}

/// Un combinador híbrido KEM adaptado sobre BYTES.
pub trait AdaptadorHibrido {
    fn nombre(&self) -> &str;
    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// `(ct, ss)` — `ct` es el ciphertext híbrido COMBINADO.
    fn encaps(&self, pk: &[u8], semilla: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), String>;
    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String>;
    /// Los COMPONENTES del ciphertext combinado: `(nombre, inicio, fin)`. Cada uno
    /// DEBE estar ligado al secreto (manipularlo cambia el secreto).
    fn componentes_ct(&self) -> &'static [(&'static str, usize, usize)];
}

/// Oráculo de BINDING: por cada componente del ciphertext, le voltea bytes y exige
/// que el secreto derivado CAMBIE. Si no cambia, el componente no está ligado.
///
/// # Errors
/// Solo si `keygen`/`encaps` base impiden montar el caso.
pub fn binding_hibrido(a: &dyn AdaptadorHibrido, casos: &[CasoHibrido]) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let corrida = (|| -> Result<(), String> {
        for (i, c) in casos.iter().enumerate() {
            let i = i as u32;
            let (pk, sk) = a.keygen(&c.semilla_clave)?;
            let (ct, ss) = a.encaps(&pk, &c.semilla_encaps)?;

            // round-trip.
            match a.decaps(&sk, &ct) {
                Ok(s) if s == ss => {}
                Ok(_) => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RoundTrip,
                    detalle: "decaps(ct válido) no recupera el secreto de encaps".into(),
                }),
                Err(e) => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RoundTrip,
                    detalle: format!("decaps(ct válido) erró: {e}"),
                }),
            }

            // binding: cada componente debe cambiar el secreto al manipularlo.
            for &(nombre, ini, fin) in a.componentes_ct() {
                if fin > ct.len() || ini >= fin {
                    continue;
                }
                for pos in [ini, (ini + fin) / 2, fin - 1] {
                    let mut ctm = ct.clone();
                    ctm[pos] ^= 0x01;
                    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.decaps(&sk, &ctm)));
                    match r {
                        Err(_) => inf.divergencias.push(Divergencia {
                            caso: i,
                            clase: Clase::Panico,
                            detalle: format!("decaps PANICÓ al manipular {nombre}@{pos}"),
                        }),
                        Ok(Ok(ss_t)) if ss_t == ss => inf.divergencias.push(Divergencia {
                            caso: i,
                            clase: Clase::NoLigado,
                            detalle: format!(
                                "manipular el componente {nombre}@{pos} NO cambió el secreto (no está ligado)"
                            ),
                        }),
                        // decaps que RECHAZA (Err) un componente manipulado es aceptable:
                        // no comparamos secretos y no es violación de binding.
                        Ok(_) => {}
                    }
                }
            }
        }
        Ok(())
    })();
    std::panic::set_hook(hook);
    corrida?;
    Ok(inf)
}

/// OBJETIVO HÍBRIDO 1: `hackerbirds/x-wing-rust` @ `2b4e67a` — el combinador X-Wing.
pub struct XWing768;

impl AdaptadorHibrido for XWing768 {
    fn nombre(&self) -> &str {
        "x-wing/hackerbirds@2b4e67a"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (sk, pk) = x_wing::XWing::generate_key_pair(SemillaRng { data: *semilla });
        Ok((pk.to_bytes().to_vec(), sk.to_bytes().to_vec()))
    }

    fn encaps(&self, pk: &[u8], semilla: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let arr: [u8; 1216] = pk
            .try_into()
            .map_err(|_| format!("pk largo {} != 1216", pk.len()))?;
        let pk = x_wing::PublicKey::from_bytes(arr).map_err(|_| "pk inválida".to_string())?;
        // `encapsulate_deterministic` es #[cfg(test)] en el crate; usamos `encapsulate`
        // con el RNG-semilla (determinista por la semilla del caso). El binding no
        // depende de qué secreto salga, solo de que CAMBIE al tocar un componente.
        let m: [u8; 32] = semilla[..32].try_into().unwrap();
        let (ss, ct) = x_wing::XWing::encapsulate(SemillaRng { data: m }, &pk);
        Ok((ct.to_bytes().to_vec(), ss.to_bytes().to_vec()))
    }

    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        let sk_arr: [u8; 32] = sk
            .try_into()
            .map_err(|_| format!("sk largo {} != 32", sk.len()))?;
        let ct_arr: [u8; 1120] = ct
            .try_into()
            .map_err(|_| format!("ct largo {} != 1120", ct.len()))?;
        let sk = x_wing::SecretKey::from_bytes(sk_arr);
        let ct = x_wing::Ciphertext::from_bytes(ct_arr).map_err(|_| "ct inválido".to_string())?;
        Ok(x_wing::XWing::decapsulate(ct, &sk).to_bytes().to_vec())
    }

    fn componentes_ct(&self) -> &'static [(&'static str, usize, usize)] {
        &[("ML-KEM", 0, 1088), ("X25519", 1088, 1120)]
    }
}

/// Control ROJO (D33): un híbrido deliberadamente NON-BINDING — ML-KEM-768 real con
/// una "cola clásica" de 32 B que viaja en el ciphertext pero que el KDF IGNORA. El
/// oráculo DEBE marcar la cola como no ligada y, a la vez, NO marcar el componente
/// ML-KEM (que sí está ligado): discrimina por los dos lados.
pub struct HibridoRoto;

impl AdaptadorHibrido for HibridoRoto {
    fn nombre(&self) -> &str {
        "HIBRIDO-ROTO(control)"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        use fips203::ml_kem_768;
        use fips203::traits::{KeyGen, SerDes};
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(*semilla, *semilla);
        let mut pk = ek.into_bytes().to_vec(); // 1184
        pk.extend_from_slice(&[0u8; 32]); // pk clásica falsa (no se usa) → 1216
        Ok((pk, dk.into_bytes().to_vec()))
    }

    fn encaps(&self, pk: &[u8], semilla: &[u8; 64]) -> Result<(Vec<u8>, Vec<u8>), String> {
        use fips203::ml_kem_768;
        use fips203::traits::{Encaps, SerDes};
        let arr: [u8; ml_kem_768::EK_LEN] = pk[..ml_kem_768::EK_LEN]
            .try_into()
            .map_err(|_| "pk corta".to_string())?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(arr).map_err(str::to_string)?;
        let m: [u8; 32] = semilla[..32].try_into().unwrap();
        let (ss, ct_m) = ek
            .try_encaps_with_rng(&mut SemillaRng { data: m })
            .map_err(str::to_string)?;
        let mut ct = ct_m.into_bytes().to_vec(); // 1088
        ct.extend_from_slice(&semilla[32..64]); // cola clásica de 32 B, NO ligada → 1120
        Ok((ct, ss.into_bytes().to_vec()))
    }

    fn decaps(&self, sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        use fips203::ml_kem_768;
        use fips203::traits::{Decaps, SerDes};
        let dk_arr: [u8; ml_kem_768::DK_LEN] = sk
            .try_into()
            .map_err(|_| "dk largo".to_string())?;
        // IGNORA la cola clásica ct[1088..]: ahí está el defecto (non-binding).
        let ct_arr: [u8; ml_kem_768::CT_LEN] = ct[..ml_kem_768::CT_LEN]
            .try_into()
            .map_err(|_| "ct corto".to_string())?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr).map_err(str::to_string)?;
        let ctt = ml_kem_768::CipherText::try_from_bytes(ct_arr).map_err(str::to_string)?;
        Ok(dk.try_decaps(&ctt).map_err(str::to_string)?.into_bytes().to_vec())
    }

    fn componentes_ct(&self) -> &'static [(&'static str, usize, usize)] {
        &[("ML-KEM", 0, 1088), ("clasico-no-ligado", 1088, 1120)]
    }
}

#[cfg(test)]
mod pruebas {
    use super::{binding_hibrido, CasoHibrido, HibridoRoto};
    use crate::Clase;

    // D33 — el control rojo se caza por la cola NO ligada, y NO hay falso positivo
    // sobre el componente ML-KEM (que sí está ligado): discrimina por ambos lados.
    #[test]
    fn roto_caza_solo_la_cola() {
        let casos = CasoHibrido::lote(4);
        let inf = binding_hibrido(&HibridoRoto, &casos).unwrap();
        assert!(
            inf.divergencias
                .iter()
                .any(|d| d.clase == Clase::NoLigado && d.detalle.contains("clasico-no-ligado")),
            "no cazó la cola no ligada: {:?}",
            inf.divergencias
        );
        assert!(
            !inf.divergencias.iter().any(|d| d.detalle.contains("ML-KEM")),
            "FALSO POSITIVO: marcó el componente ML-KEM, que SÍ está ligado: {:?}",
            inf.divergencias
        );
    }
}
