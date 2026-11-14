// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán.
//
// Oráculo v2 — ML-KEM (FIPS 203) y la capa HÍBRIDA. El ML-DSA ya maduro salió seco
// contra targets cuidados; la ola 2026 mete más bugs en el KEM y en los combinadores
// híbridos (X25519+ML-KEM). La JOYA es single-impl y no necesita una segunda
// implementación: el **rechazo implícito** de ML-KEM (el corazón de la transformación
// Fujisaki-Okamoto que da seguridad CCA). `decaps` de un ciphertext manipulado DEBE
// devolver un secreto pseudo-aleatorio DETERMINISTA (derivado de z‖ct), nunca el
// secreto real, nunca un error, nunca un pánico. Un from-scratch que lo implementa
// como "si el ct es inválido, error" o "devuelve el secreto igual" tiene un CCA break.

use crate::{Clase, Divergencia, Informe};
use fips203::ml_kem_768;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};

/// RNG determinista que devuelve una semilla de 32 B: para que `encaps` (que toma su
/// mensaje `m` del RNG) sea REPRODUCIBLE (D30), no azaroso.
pub(crate) struct SemillaRng {
    pub(crate) data: [u8; 32],
}

impl rand_core::RngCore for SemillaRng {
    fn next_u32(&mut self) -> u32 {
        unimplemented!("SemillaRng solo sirve para rellenar los 32 B de m")
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!("SemillaRng solo sirve para rellenar los 32 B de m")
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Rellena ciclando la semilla: robusto a cualquier longitud de extracción
        // (ML-KEM extrae 32 B; combinadores híbridos pueden extraer más de una vez).
        for (i, b) in dest.iter_mut().enumerate() {
            *b = self.data[i % 32];
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SemillaRng {}

/// Caso determinista para el KEM: keygen desde (d, z) y encaps desde m. Todo de
/// semillas fijas (sin RNG): dos impl conformes producen lo mismo.
#[derive(Clone, Debug)]
pub struct CasoKem {
    pub semilla_d: [u8; 32],
    pub semilla_z: [u8; 32],
    pub semilla_m: [u8; 32],
}

impl CasoKem {
    /// `n` casos reproducibles a partir de un contador.
    #[must_use]
    pub fn lote(n: u32) -> Vec<CasoKem> {
        (0..n)
            .map(|i| {
                let mk = |sal: u32, tag: u8| {
                    let mut s = [0u8; 32];
                    s[..4].copy_from_slice(&i.wrapping_add(sal).to_le_bytes());
                    s[31] = tag;
                    s
                };
                CasoKem {
                    semilla_d: mk(0, 0xD0),
                    semilla_z: mk(0x9E37_79B9, 0x2E),
                    semilla_m: mk(0x85EB_CA6B, 0x3C),
                }
            })
            .collect()
    }
}

/// Cualquier ML-KEM se adapta a esta interfaz sobre BYTES serializados.
pub trait AdaptadorMlKem {
    fn nombre(&self) -> &str;
    /// KeyGen_internal desde (d, z). Devuelve `(ek_bytes, dk_bytes)`.
    fn keygen(&self, d: &[u8; 32], z: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// Encaps determinista con mensaje `m`. Devuelve `(ss_bytes, ct_bytes)`.
    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// Decaps. `Ok(ss)` incluso con ct manipulado (rechazo implícito); `Err` SOLO si
    /// la impl se niega a producir un secreto (lo cual es, en sí, un hallazgo).
    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String>;
}

/// Adaptador de referencia: el crate `fips203` (ml-kem-768), bien probado.
pub struct Fips203_768;

impl AdaptadorMlKem for Fips203_768 {
    fn nombre(&self) -> &str {
        "fips203/ml-kem-768"
    }

    fn keygen(&self, d: &[u8; 32], z: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (ek, dk) = ml_kem_768::KG::keygen_from_seed(*d, *z);
        Ok((ek.into_bytes().to_vec(), dk.into_bytes().to_vec()))
    }

    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let arr: [u8; ml_kem_768::EK_LEN] = ek
            .try_into()
            .map_err(|_| format!("ek largo {} != {}", ek.len(), ml_kem_768::EK_LEN))?;
        let ek = ml_kem_768::EncapsKey::try_from_bytes(arr).map_err(str::to_string)?;
        let (ss, ct) = ek
            .try_encaps_with_rng(&mut SemillaRng { data: *m })
            .map_err(str::to_string)?;
        Ok((ss.into_bytes().to_vec(), ct.into_bytes().to_vec()))
    }

    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        let dk_arr: [u8; ml_kem_768::DK_LEN] = dk
            .try_into()
            .map_err(|_| format!("dk largo {} != {}", dk.len(), ml_kem_768::DK_LEN))?;
        let ct_arr: [u8; ml_kem_768::CT_LEN] = ct
            .try_into()
            .map_err(|_| format!("ct largo {} != {}", ct.len(), ml_kem_768::CT_LEN))?;
        let dk = ml_kem_768::DecapsKey::try_from_bytes(dk_arr).map_err(str::to_string)?;
        let ct = ml_kem_768::CipherText::try_from_bytes(ct_arr).map_err(str::to_string)?;
        let ss = dk.try_decaps(&ct).map_err(str::to_string)?;
        Ok(ss.into_bytes().to_vec())
    }
}

/// OBJETIVO KEM 1: `QuantumDrizzy/Bastion @ 052496028` (ML-KEM-768 from-scratch).
/// API byte-native (`keygen_derand`/`encaps_derand`/`decaps`). Su `decaps` es
/// infalible (`[u8;32]`), señal de que intenta el rechazo implícito; el oráculo
/// confirma si lo hace BIEN.
pub struct BastionKem768;

impl AdaptadorMlKem for BastionKem768 {
    fn nombre(&self) -> &str {
        "bastion-kem/QuantumDrizzy@052496028"
    }

    fn keygen(&self, d: &[u8; 32], z: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (ek, dk) = bastion::kem::kem::keygen_derand(d, z);
        Ok((ek.to_vec(), dk.to_vec()))
    }

    fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let ek_arr: [u8; 1184] = ek
            .try_into()
            .map_err(|_| format!("ek largo {} != 1184", ek.len()))?;
        // Bastion devuelve (ct, ss); el trait pide (ss, ct).
        let (ct, ss) = bastion::kem::kem::encaps_derand(&ek_arr, m);
        Ok((ss.to_vec(), ct.to_vec()))
    }

    fn decaps(&self, dk: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
        let dk_arr: [u8; 2400] = dk
            .try_into()
            .map_err(|_| format!("dk largo {} != 2400", dk.len()))?;
        let ct_arr: [u8; 1088] = ct
            .try_into()
            .map_err(|_| format!("ct largo {} != 1088", ct.len()))?;
        Ok(bastion::kem::kem::decaps(&dk_arr, &ct_arr).to_vec())
    }
}

/// Varias formas de manipular un ciphertext (del largo correcto) para la sonda de
/// rechazo implícito. Cada una debe gatillar el rechazo (secreto ≠ real), no un
/// error ni el secreto verdadero.
fn cts_manipulados(ct: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let n = ct.len();
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let mut flip = |etq: &'static str, idx: usize| {
        let mut m = ct.to_vec();
        m[idx] ^= 0x01;
        out.push((etq, m));
    };
    flip("ct: flip byte 0", 0);
    flip("ct: flip byte medio", n / 2);
    flip("ct: flip último byte", n - 1);
    out.push(("ct: todo a cero", vec![0u8; n]));
    out.push(("ct: todo 0xFF", vec![0xFFu8; n]));
    out
}

/// Oráculo de SEGURIDAD del KEM (single-impl, la joya). Verifica, sobre una sola
/// implementación: round-trip, determinismo de keygen/encaps, y sobre todo el
/// RECHAZO IMPLÍCITO: `decaps` de un ct manipulado debe devolver un secreto que (a)
/// NO es el real, (b) es DETERMINISTA, (c) no es un error, (d) no panica.
///
/// # Errors
/// Solo si `keygen`/`encaps` base impiden montar el caso.
pub fn seguridad_kem(a: &dyn AdaptadorMlKem, casos: &[CasoKem]) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let corrida = (|| -> Result<(), String> {
        for (i, c) in casos.iter().enumerate() {
            let i = i as u32;
            let (ek, dk) = a.keygen(&c.semilla_d, &c.semilla_z)?;

            // determinismo de keygen.
            let (ek2, _) = a.keygen(&c.semilla_d, &c.semilla_z)?;
            if ek != ek2 {
                inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::NoDeterminista,
                    detalle: "keygen de la misma semilla da ek distinta".into(),
                });
            }

            let (ss, ct) = a.encaps(&ek, &c.semilla_m)?;

            // round-trip: decaps del ct bueno recupera el secreto.
            match a.decaps(&dk, &ct) {
                Ok(ss_rt) if ss_rt == ss => {}
                Ok(_) => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RoundTrip,
                    detalle: "decaps(ct válido) NO recupera el secreto de encaps".into(),
                }),
                Err(e) => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RoundTrip,
                    detalle: format!("decaps(ct válido) erró: {e}"),
                }),
            }

            // RECHAZO IMPLÍCITO sobre cada ct manipulado.
            for (etq, ctm) in cts_manipulados(&ct) {
                // (d) no panica.
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.decaps(&dk, &ctm)));
                let Ok(res) = r else {
                    inf.divergencias.push(Divergencia {
                        caso: i,
                        clase: Clase::Panico,
                        detalle: format!("decaps PANICÓ con {etq}"),
                    });
                    continue;
                };
                match res {
                    // (c) no error: debe devolver un secreto (rechazo implícito), no negarse.
                    Err(e) => inf.divergencias.push(Divergencia {
                        caso: i,
                        clase: Clase::RechazoImplicito,
                        detalle: format!("[{etq}] decaps ERRÓ ({e}) en vez de rechazar implícitamente"),
                    }),
                    Ok(ss_rej) => {
                        // (a) no filtra el secreto real.
                        if ss_rej == ss {
                            inf.divergencias.push(Divergencia {
                                caso: i,
                                clase: Clase::RechazoImplicito,
                                detalle: format!("[{etq}] decaps devolvió el SECRETO REAL con ct manipulado (CCA break)"),
                            });
                        }
                        // (b) el rechazo es determinista.
                        if let Ok(ss_rej2) = a.decaps(&dk, &ctm)
                            && ss_rej2 != ss_rej {
                                inf.divergencias.push(Divergencia {
                                    caso: i,
                                    clase: Clase::RechazoImplicito,
                                    detalle: format!("[{etq}] el secreto de rechazo NO es determinista"),
                                });
                            }
                    }
                }
            }

            // robustez: dk/ct de largo anómalo no deben panicar (error limpio sí).
            for (etq, dkx, ctx) in [
                ("ct truncado", dk.clone(), ct[..ct.len().saturating_sub(1)].to_vec()),
                ("ct vacío", dk.clone(), vec![]),
                ("dk vacío", vec![], ct.clone()),
            ] {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.decaps(&dkx, &ctx)));
                if r.is_err() {
                    inf.divergencias.push(Divergencia {
                        caso: i,
                        clase: Clase::Panico,
                        detalle: format!("decaps PANICÓ con {etq}"),
                    });
                }
            }
        }
        Ok(())
    })();
    std::panic::set_hook(hook);
    corrida?;
    Ok(inf)
}

/// Oráculo DIFERENCIAL del KEM: exige a dos impl la misma ek/dk/ct/ss byte-a-byte
/// sobre entrada determinista, y binding cruzado (la decaps de una recupera el
/// secreto de la encaps de la otra cuando las claves coinciden).
///
/// # Errors
/// Solo si una operación base impide comparar.
pub fn diferencial_kem(
    a: &dyn AdaptadorMlKem,
    b: &dyn AdaptadorMlKem,
    casos: &[CasoKem],
) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    for (i, c) in casos.iter().enumerate() {
        let i = i as u32;
        let (eka, dka) = a.keygen(&c.semilla_d, &c.semilla_z)?;
        let (ekb, dkb) = b.keygen(&c.semilla_d, &c.semilla_z)?;
        if eka != ekb {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::ClavePublica,
                detalle: format!("ek difieren ({} vs {} B)", eka.len(), ekb.len()),
            });
        }
        let (ssa, cta) = a.encaps(&eka, &c.semilla_m)?;
        let (ssb, ctb) = b.encaps(&ekb, &c.semilla_m)?;
        if cta != ctb {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::FirmaBytes,
                detalle: "ciphertexts deterministas distintos byte-a-byte".into(),
            });
        }
        if ssa != ssb {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::FirmaBytes,
                detalle: "secretos de encaps distintos byte-a-byte".into(),
            });
        }
        // binding cruzado: si las claves coinciden, b.decaps del ct de a da ssa.
        if eka == ekb && dka == dkb {
            if let Ok(ss) = b.decaps(&dkb, &cta)
                && ss != ssa {
                    inf.divergencias.push(Divergencia {
                        caso: i,
                        clase: Clase::VerificacionCruzada,
                        detalle: format!("{} no recupera el secreto de {}", b.nombre(), a.nombre()),
                    });
                }
            // RECHAZO IMPLÍCITO conforme: con un ct manipulado, ambas impl deben dar
            // el MISMO secreto de rechazo J(z,ct). Discrepar = una no implementa el
            // rechazo implícito como FIPS-203 (el break sutil que el single-impl no ve).
            let mut ctm = cta.clone();
            if let Some(b0) = ctm.first_mut() {
                *b0 ^= 0x01;
            }
            match (a.decaps(&dka, &ctm), b.decaps(&dkb, &ctm)) {
                (Ok(ra), Ok(rb)) if ra != rb => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RechazoImplicito,
                    detalle: "el secreto de rechazo implícito difiere entre impl (ct manipulado)".into(),
                }),
                (Ok(_), Err(e)) | (Err(e), Ok(_)) => inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::RechazoImplicito,
                    detalle: format!("una impl erró el rechazo implícito y la otra no: {e}"),
                }),
                _ => {}
            }
        }
    }
    Ok(inf)
}

#[cfg(test)]
mod pruebas {
    use super::{diferencial_kem, seguridad_kem, AdaptadorMlKem, CasoKem, Fips203_768};
    use crate::Clase;

    // Control positivo: la referencia pasa el oráculo de seguridad limpia.
    #[test]
    fn seguridad_referencia_limpia() {
        let casos = CasoKem::lote(16);
        let inf = seguridad_kem(&Fips203_768, &casos).unwrap();
        assert!(inf.limpio(), "la referencia falló seguridad KEM: {:?}", inf.divergencias);
    }

    // Control positivo: diferencial de la referencia contra sí misma, limpio.
    #[test]
    fn diferencial_referencia_limpio() {
        let casos = CasoKem::lote(16);
        let inf = diferencial_kem(&Fips203_768, &Fips203_768, &casos).unwrap();
        assert!(inf.limpio(), "ref vs ref KEM no limpio: {:?}", inf.divergencias);
    }

    // Control ROJO (D33): un KEM cuyo decaps se NIEGA a producir un secreto (error en
    // vez de rechazo implícito) — el error from-scratch más común (tratar ML-KEM como
    // un esquema que rechaza). `seguridad_kem` DEBE cazarlo como `RechazoImplicito`
    // por la rama de error sobre el ct manipulado, por la vía real.
    struct KemErrante {
        base: Fips203_768,
    }
    impl AdaptadorMlKem for KemErrante {
        fn nombre(&self) -> &str {
            "KEM-ERRANTE(control)"
        }
        fn keygen(&self, d: &[u8; 32], z: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
            self.base.keygen(d, z)
        }
        fn encaps(&self, ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
            self.base.encaps(ek, m)
        }
        fn decaps(&self, _dk: &[u8], _ct: &[u8]) -> Result<Vec<u8>, String> {
            Err("control: decaps se niega a rechazar implícitamente".into())
        }
    }

    #[test]
    fn seguridad_caza_errante() {
        let casos = CasoKem::lote(4);
        let inf = seguridad_kem(&KemErrante { base: Fips203_768 }, &casos).unwrap();
        assert!(!inf.limpio(), "no cazó el KEM errante: la sonda no discrimina");
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::RechazoImplicito),
            "esperaba RechazoImplicito, hubo: {:?}",
            inf.divergencias
        );
    }
}
