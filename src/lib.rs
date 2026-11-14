// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán — oráculo adversario de implementaciones PQC de terceros.
//
// v0: oráculo DIFERENCIAL + de CONFORMIDAD para ML-DSA (FIPS 204), la capa de
// firma post-cuántica que la ola de migración 2026 está desplegando a las carreras
// y que va años por detrás del KEM en madurez.
//
// El método (destilado del arnés diferencial de Iraca, D9): se conduce a CADA
// implementación con la MISMA entrada determinista y se exige igualdad byte-a-byte.
// Una divergencia en cualquier capa —clave, firma o verificación cruzada— es un
// hallazgo. El adaptador trabaja sobre BYTES serializados, así que una impl de
// tercero (crate, CLI, FFI) se enchufa sin tocar el motor.

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

/// Adaptadores de implementaciones de TERCEROS bajo diferencial (objetivos de caza).
pub mod objetivos;
pub use objetivos::{Bastion65, MlDsaRs65};

/// OBJETIVO 5 (QRL/Zond) — HILO 3: diferencial ML-DSA-87 de 3 vías
/// (fips204 ↔ rust-qrllib ↔ go-qrllib CLI). QRL = bounty standing, PQC-nativo.
pub mod qrl;
pub use qrl::{Fips204_87, QrlGo87, QrlRust87};

/// Oráculo v2: ML-KEM (FIPS 203) y la capa HÍBRIDA — foco en el rechazo implícito
/// (seguridad CCA), binding y downgrade, donde la ola 2026 mete más bugs que en el
/// ML-DSA ya maduro.
pub mod kem;

/// Oráculo v2 — combinadores HÍBRIDOS (X25519+ML-KEM). Foco en el BINDING: todo
/// componente del ciphertext debe estar ligado al secreto derivado.
pub mod hibrido;

/// Oráculo AEAD — diferencial de implementaciones "roll-your-own" de ChaCha20-
/// Poly1305 / AES-GCM contra el crate auditado (Poly1305/GHASH a mano = bordes).
pub mod aead;

/// Evidencia tipada + libro de obligaciones: nuestra disciplina D30/D31/D33 vuelta
/// tipo. Un hallazgo solo se reporta `confirmado` si su `Afirmacion` está `Cerrada`,
/// y una afirmación solo cierra con un VERIFICADOR presente (no por ausencia de prueba).
pub mod evidencia;
pub use evidencia::{Afirmacion, Autoridad, Estado, Evidencia, Libro};

/// Un caso de prueba determinista: todo sale de semillas fijas, nada de azar,
/// para que dos implementaciones conformes PRODUZCAN LO MISMO (D33: el control
/// se valida contra el artefacto, no se fabrica).
#[derive(Clone, Debug)]
pub struct Caso {
    pub semilla_clave: [u8; 32],
    pub semilla_firma: [u8; 32],
    pub mensaje: Vec<u8>,
    pub contexto: Vec<u8>,
}

impl Caso {
    /// Genera `n` casos reproducibles a partir de un contador (sin RNG: la
    /// reproducibilidad es parte del oráculo, D30).
    #[must_use]
    pub fn lote(n: u32) -> Vec<Caso> {
        (0..n)
            .map(|i| {
                let mut sc = [0u8; 32];
                let mut sf = [0u8; 32];
                sc[..4].copy_from_slice(&i.to_le_bytes());
                sf[..4].copy_from_slice(&i.wrapping_add(0x9E37_79B9).to_le_bytes());
                sc[31] = 0xA5;
                sf[31] = 0x5A;
                Caso {
                    semilla_clave: sc,
                    semilla_firma: sf,
                    mensaje: format!("mohan-caso-{i}").into_bytes(),
                    contexto: if i % 2 == 0 { vec![] } else { vec![0xC0, i as u8] },
                }
            })
            .collect()
    }
}

/// La clase de cada divergencia encontrada: nombra POR DÓNDE falló, no solo que falló.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Clase {
    /// Las claves públicas derivadas de la misma semilla no coinciden byte-a-byte.
    ClavePublica,
    /// Las firmas deterministas de la misma entrada no coinciden byte-a-byte.
    FirmaBytes,
    /// Una impl NO verifica la firma producida por la otra (binding roto).
    VerificacionCruzada,
    /// La propia impl no verifica su propia firma (round-trip roto).
    RoundTrip,
    /// La impl ACEPTA una firma manipulada (no rechaza lo que debe).
    AceptaManipulada,
    /// La impl no es determinista: misma entrada, salida distinta entre dos corridas.
    NoDeterminista,
    /// La impl PANICÓ con bytes controlados por el atacante (pk/firma malformada):
    /// un `verify` que entra por la red y aborta es una denegación de servicio.
    Panico,
    /// El objetivo y la referencia DISCREPAN sobre una firma mutada estructuralmente:
    /// si el objetivo ACEPTA donde la referencia rechaza, su `verify` es laxo (no
    /// valida la canonicidad FIPS-204) → maleabilidad / forja.
    Maleable,
    /// ML-KEM: el `decaps` de un ciphertext manipulado NO hace el rechazo implícito
    /// correcto (devuelve el secreto REAL, o ERRÓ en vez de devolver un secreto, o
    /// el secreto de rechazo no es determinista). Es el núcleo de seguridad CCA.
    RechazoImplicito,
    /// Híbrido: manipular un COMPONENTE del ciphertext (p. ej. la parte X25519) NO
    /// cambia el secreto derivado → ese componente no está LIGADO al KDF. Un
    /// combinador non-binding abre la vía a downgrade / ataque por-componente.
    NoLigado,
}

#[derive(Clone, Debug)]
pub struct Divergencia {
    pub caso: u32,
    pub clase: Clase,
    pub detalle: String,
}

/// Cualquier implementación de ML-DSA se adapta a esta interfaz, operando sobre
/// BYTES serializados (impl-agnóstica: crate, subproceso o FFI).
pub trait AdaptadorMlDsa {
    fn nombre(&self) -> &str;
    /// Deriva un par de claves desde una semilla de 32 B. `(pk_bytes, sk_bytes)`.
    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String>;
    /// Firma determinista; `sk` es lo que devolvió `keygen`.
    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String>;
    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool;
}

/// Adaptador de referencia: el crate `fips204` (ml-dsa-65), bien probado, que sirve
/// de patrón contra el que se diferencian los terceros.
pub struct Fips204_65;

impl AdaptadorMlDsa for Fips204_65 {
    fn nombre(&self) -> &str {
        "fips204/ml-dsa-65"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(semilla);
        Ok((pk.into_bytes().to_vec(), sk.into_bytes().to_vec()))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let arr: [u8; ml_dsa_65::SK_LEN] = sk
            .try_into()
            .map_err(|_| format!("sk con largo {} != {}", sk.len(), ml_dsa_65::SK_LEN))?;
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(arr).map_err(|e| e.to_string())?;
        let sig = sk
            .try_sign_with_seed(semilla_firma, msg, ctx)
            .map_err(|e| e.to_string())?;
        Ok(sig.to_vec())
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let Ok(pk_arr): Result<[u8; ml_dsa_65::PK_LEN], _> = pk.try_into() else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; ml_dsa_65::SIG_LEN], _> = sig.try_into() else {
            return false;
        };
        let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_arr) else {
            return false;
        };
        pk.verify(msg, &sig_arr, ctx)
    }
}

/// Mutante de control (D33): envuelve un adaptador real y corrompe UN byte de cada
/// firma. Existe para que el banco demuestre que el oráculo DISCRIMINA por la vía
/// real (la comparación de bytes y la verificación cruzada), no por el arnés.
pub struct Mutante<A: AdaptadorMlDsa> {
    pub base: A,
}

impl<A: AdaptadorMlDsa> AdaptadorMlDsa for Mutante<A> {
    fn nombre(&self) -> &str {
        "MUTANTE(control)"
    }
    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.base.keygen(semilla)
    }
    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        let mut sig = self.base.firmar(sk, msg, ctx, semilla_firma)?;
        if let Some(b) = sig.first_mut() {
            *b ^= 0x01; // una divergencia real, mínima, en la firma
        }
        Ok(sig)
    }
    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        self.base.verificar(pk, msg, ctx, sig)
    }
}

/// Resultado agregado de una corrida del oráculo.
#[derive(Clone, Debug, Default)]
pub struct Informe {
    pub casos: u32,
    pub divergencias: Vec<Divergencia>,
}

impl Informe {
    #[must_use]
    pub fn limpio(&self) -> bool {
        self.divergencias.is_empty()
    }
}

/// Corre el oráculo DIFERENCIAL entre dos implementaciones sobre un lote de casos.
/// Exige: misma clave pública, misma firma byte-a-byte, verificación cruzada en
/// ambos sentidos, round-trip propio y rechazo de firma manipulada.
///
/// # Errors
/// Devuelve `Err` solo si una operación criptográfica base falla de forma que
/// impide siquiera comparar (p. ej. `keygen` revienta); una DIVERGENCIA no es un
/// error, es el hallazgo, y va en el `Informe`.
pub fn diferencial(
    a: &dyn AdaptadorMlDsa,
    b: &dyn AdaptadorMlDsa,
    casos: &[Caso],
) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    for (i, c) in casos.iter().enumerate() {
        let i = i as u32;
        let (pka, ska) = a.keygen(&c.semilla_clave)?;
        let (pkb, skb) = b.keygen(&c.semilla_clave)?;

        if pka != pkb {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::ClavePublica,
                detalle: format!("pk difieren ({} vs {} B)", pka.len(), pkb.len()),
            });
        }

        let siga = a.firmar(&ska, &c.mensaje, &c.contexto, &c.semilla_firma)?;
        let sigb = b.firmar(&skb, &c.mensaje, &c.contexto, &c.semilla_firma)?;

        if siga != sigb {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::FirmaBytes,
                detalle: "firmas deterministas distintas byte-a-byte".into(),
            });
        }

        // round-trip de cada una
        if !a.verificar(&pka, &c.mensaje, &c.contexto, &siga) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::RoundTrip,
                detalle: format!("{} no verifica su propia firma", a.nombre()),
            });
        }
        if !b.verificar(&pkb, &c.mensaje, &c.contexto, &sigb) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::RoundTrip,
                detalle: format!("{} no verifica su propia firma", b.nombre()),
            });
        }

        // verificación cruzada (binding): si las claves coinciden, cada una debe
        // aceptar la firma de la otra.
        if pka == pkb {
            if !b.verificar(&pkb, &c.mensaje, &c.contexto, &siga) {
                inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::VerificacionCruzada,
                    detalle: format!("{} rechaza firma de {}", b.nombre(), a.nombre()),
                });
            }
            if !a.verificar(&pka, &c.mensaje, &c.contexto, &sigb) {
                inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::VerificacionCruzada,
                    detalle: format!("{} rechaza firma de {}", a.nombre(), b.nombre()),
                });
            }
        }
    }
    Ok(inf)
}

/// Oráculo de CONFORMIDAD de una sola implementación: invariantes que cualquier
/// ML-DSA conforme DEBE cumplir, sin necesitar una segunda impl.
/// Determinismo, round-trip, y rechazo de firma/mensaje/contexto manipulados.
///
/// # Errors
/// Igual que `diferencial`: solo si una operación base impide la comprobación.
pub fn conformidad(a: &dyn AdaptadorMlDsa, casos: &[Caso]) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    for (i, c) in casos.iter().enumerate() {
        let i = i as u32;
        let (pk, sk) = a.keygen(&c.semilla_clave)?;
        let (pk2, _) = a.keygen(&c.semilla_clave)?;
        if pk != pk2 {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::NoDeterminista,
                detalle: "keygen de la misma semilla da claves distintas".into(),
            });
        }

        let sig = a.firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)?;
        let sig2 = a.firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)?;
        if sig != sig2 {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::NoDeterminista,
                detalle: "firma determinista de la misma entrada difiere".into(),
            });
        }

        if !a.verificar(&pk, &c.mensaje, &c.contexto, &sig) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::RoundTrip,
                detalle: "no verifica su propia firma".into(),
            });
        }

        // negativos: el que verifica DEBE rechazar.
        let mut sig_mal = sig.clone();
        if let Some(b) = sig_mal.first_mut() {
            *b ^= 0x01;
        }
        if a.verificar(&pk, &c.mensaje, &c.contexto, &sig_mal) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::AceptaManipulada,
                detalle: "acepta firma con un byte alterado".into(),
            });
        }
        let msg_mal = [c.mensaje.as_slice(), b"x"].concat();
        if a.verificar(&pk, &msg_mal, &c.contexto, &sig) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::AceptaManipulada,
                detalle: "acepta firma sobre mensaje alterado".into(),
            });
        }
    }
    Ok(inf)
}

/// Bytes basura deterministas del largo pedido (LCG sembrado por el caso + sal),
/// para que las sondas de robustez sean reproducibles (D30).
fn basura(largo: usize, c: &Caso, sal: u8) -> Vec<u8> {
    let mut x = u32::from_le_bytes([c.semilla_clave[0], c.semilla_clave[1], sal, 0x9E]);
    let mut v = Vec::with_capacity(largo);
    for _ in 0..largo {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((x >> 24) as u8);
    }
    v
}

/// Llama a `verificar` bajo `catch_unwind`: un PÁNICO con bytes malformados es el
/// hallazgo (DoS); un `true` sobre una entrada que NO corresponde es aceptación
/// indebida. Un `false` limpio es el comportamiento correcto.
// Helper de sonda: 8 parámetros son inherentes (pk/msg/ctx/sig son la entrada AEAD-DSA
// completa + el caso/etiqueta/informe para el registro); empaquetarlos en un struct
// oscurecería la llamada, no la aclararía.
#[allow(clippy::too_many_arguments)]
fn sondear(
    a: &dyn AdaptadorMlDsa,
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
    caso: u32,
    etq: &str,
    inf: &mut Informe,
) {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| a.verificar(pk, msg, ctx, sig)));
    match r {
        Err(_) => inf.divergencias.push(Divergencia {
            caso,
            clase: Clase::Panico,
            detalle: format!("verify PANICÓ con {etq}"),
        }),
        Ok(true) => inf.divergencias.push(Divergencia {
            caso,
            clase: Clase::AceptaManipulada,
            detalle: format!("verify aceptó {etq}"),
        }),
        Ok(false) => {}
    }
}

/// Oráculo de ROBUSTEZ: alimenta `verify` con pk/firma malformadas (la superficie
/// que entra por la red) y exige que RECHACE sin PANICAR. Encuentra una clase
/// distinta a la conformidad byte-a-byte: pánico/índice/overflow en el parseo de
/// bytes del atacante = denegación de servicio.
///
/// # Errors
/// Solo si `keygen`/`firmar` base fallan de forma que impiden generar el par válido
/// del que derivar las entradas malformadas.
pub fn robustez(a: &dyn AdaptadorMlDsa, casos: &[Caso]) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    // Silenciar el hook de pánico durante las sondas (se restaura después), para que
    // un pánico esperado no ensucie la salida; el `catch_unwind` sigue atrapándolo.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let corrida = (|| -> Result<(), String> {
        for (i, c) in casos.iter().enumerate() {
            let i = i as u32;
            let (pk, sk) = a.keygen(&c.semilla_clave)?;
            let sig = a.firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)?;

            // pk/firma del LARGO correcto pero bytes basura (el caso jugoso: el parseo
            // estructural con contenido inválido es donde revienta una impl joven).
            let pk_basura = basura(pk.len(), c, 0xB0);
            sondear(a, &pk_basura, &c.mensaje, &c.contexto, &sig, i, "pk basura (largo correcto)", &mut inf);
            let sig_basura = basura(sig.len(), c, 0x51);
            sondear(a, &pk, &c.mensaje, &c.contexto, &sig_basura, i, "firma basura (largo correcto)", &mut inf);

            // largos anómalos: truncado y extendido, en pk y firma.
            let pk_trunc = pk[..pk.len().saturating_sub(1)].to_vec();
            let mut pk_ext = pk.clone();
            pk_ext.push(0);
            sondear(a, &pk_trunc, &c.mensaje, &c.contexto, &sig, i, "pk truncada", &mut inf);
            sondear(a, &pk_ext, &c.mensaje, &c.contexto, &sig, i, "pk extendida", &mut inf);

            let sig_trunc = sig[..sig.len().saturating_sub(1)].to_vec();
            let mut sig_ext = sig.clone();
            sig_ext.push(0);
            sondear(a, &pk, &c.mensaje, &c.contexto, &sig_trunc, i, "firma truncada", &mut inf);
            sondear(a, &pk, &c.mensaje, &c.contexto, &sig_ext, i, "firma extendida", &mut inf);

            // vacíos.
            sondear(a, &[], &c.mensaje, &c.contexto, &sig, i, "pk vacía", &mut inf);
            sondear(a, &pk, &c.mensaje, &c.contexto, &[], i, "firma vacía", &mut inf);
        }
        Ok(())
    })();
    std::panic::set_hook(hook);
    corrida?;
    Ok(inf)
}

/// Control rojo de la sonda de robustez (D33): un adaptador cuyo `verificar` SIEMPRE
/// panica. `robustez` DEBE cazarlo como `Panico`, por la vía real del `catch_unwind`.
pub struct PanicoMutante<A: AdaptadorMlDsa> {
    pub base: A,
}

impl<A: AdaptadorMlDsa> AdaptadorMlDsa for PanicoMutante<A> {
    fn nombre(&self) -> &str {
        "PANICO(control)"
    }
    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.base.keygen(semilla)
    }
    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        self.base.firmar(sk, msg, ctx, semilla_firma)
    }
    fn verificar(&self, _pk: &[u8], _msg: &[u8], _ctx: &[u8], _sig: &[u8]) -> bool {
        panic!("control: pánico deliberado en verify")
    }
}

/// Aplica una mutación a una copia de la firma y la devuelve.
fn mut_con(sig: &[u8], f: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut m = sig.to_vec();
    f(&mut m);
    m
}

/// Mutaciones ESTRUCTURADAS de una firma ML-DSA-65 válida (layout FIPS-204:
/// `c̃`‖`z`‖`h`, con `c̃`=48 B, `h`=ω+K=55+6=61 B al final). Apuntan a la región del
/// HINT —donde vive el check de validez (HintBitUnpack devuelve ⊥ si hay bits extra,
/// índices no crecientes o peso > ω) que un `verify` from-scratch suele omitir— y a
/// `z`/`c̃`. No hace falta saber el veredicto "correcto": la referencia lo da (D33).
fn mutaciones_firma(sig: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    const CT: usize = 48; // LAMBDA/4 (c̃) para ML-DSA-65
    const OMEGA: usize = 55;
    const KK: usize = 6;
    const HINT: usize = OMEGA + KK; // 61
    let n = sig.len();
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if n < CT + HINT + 1 {
        return out; // no es un ML-DSA-65 de tamaño esperado; sin mutaciones estructurales
    }
    let h0 = n - HINT; // inicio del hint
    let cuentas = n - KK; // inicio de los K bytes de cuenta acumulada del hint

    out.push(("hint: todo a cero", mut_con(sig, |m| m[h0..].fill(0))));
    out.push(("hint: cuentas = 0xFF", mut_con(sig, |m| m[cuentas..].fill(0xFF))));
    out.push(("hint: 1ra cuenta = OMEGA+1", mut_con(sig, |m| m[cuentas] = OMEGA as u8 + 1)));
    out.push(("hint: cuentas decrecientes", mut_con(sig, |m| {
        m[cuentas] = OMEGA as u8;
        m[n - 1] = 1;
    })));
    out.push(("hint: último slot de índice a 0xFF", mut_con(sig, |m| m[cuentas - 1] = 0xFF)));
    out.push(("hint: índice[0] replicado en la cola", mut_con(sig, |m| m[cuentas - 1] = m[h0])));
    out.push(("z: bit alto del último byte de z", mut_con(sig, |m| m[h0 - 1] ^= 0x80)));
    out.push(("c-tilde: flip byte 0", mut_con(sig, |m| m[0] ^= 0x01)));
    out
}

/// Oráculo de MALEABILIDAD: toma la firma canónica válida de la referencia, la muta
/// de formas estructuradas, y compara el veredicto de `verify` de la referencia vs
/// el objetivo sobre CADA mutante (misma pk, que ya se verificó idéntica). Una
/// DISCREPANCIA es el hallazgo: si el objetivo ACEPTA donde la referencia rechaza,
/// su `verify` no valida la canonicidad FIPS-204 (maleabilidad / vía a forja).
///
/// # Errors
/// Solo si `keygen`/`firmar` base impiden producir la firma canónica de partida.
pub fn maleabilidad(
    referencia: &dyn AdaptadorMlDsa,
    objetivo: &dyn AdaptadorMlDsa,
    casos: &[Caso],
) -> Result<Informe, String> {
    let mut inf = Informe {
        casos: casos.len() as u32,
        divergencias: Vec::new(),
    };
    for (i, c) in casos.iter().enumerate() {
        let i = i as u32;
        let (pk_r, sk_r) = referencia.keygen(&c.semilla_clave)?;
        let (pk_o, _sk_o) = objetivo.keygen(&c.semilla_clave)?;
        if pk_r != pk_o {
            // Sin clave común no se puede comparar el mismo mutante; se nombra y sigue.
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::ClavePublica,
                detalle: "pk difieren: maleabilidad no comparable en este caso".into(),
            });
            continue;
        }
        let sig = referencia.firmar(&sk_r, &c.mensaje, &c.contexto, &c.semilla_firma)?;
        // Base: ambos DEBEN aceptar la firma canónica (si no, es RoundTrip, no maleabilidad).
        if !objetivo.verificar(&pk_r, &c.mensaje, &c.contexto, &sig) {
            inf.divergencias.push(Divergencia {
                caso: i,
                clase: Clase::RoundTrip,
                detalle: format!("{} rechaza la firma canónica de la referencia", objetivo.nombre()),
            });
        }
        for (etq, mutante) in mutaciones_firma(&sig) {
            let r_ref = referencia.verificar(&pk_r, &c.mensaje, &c.contexto, &mutante);
            let r_obj = objetivo.verificar(&pk_r, &c.mensaje, &c.contexto, &mutante);
            if r_ref != r_obj {
                inf.divergencias.push(Divergencia {
                    caso: i,
                    clase: Clase::Maleable,
                    detalle: format!(
                        "[{etq}] referencia={} objetivo={}{}",
                        if r_ref { "ACEPTA" } else { "rechaza" },
                        if r_obj { "ACEPTA" } else { "rechaza" },
                        if r_obj && !r_ref { "  <-- objetivo LAXO (forja)" } else { "" },
                    ),
                });
            }
        }
    }
    Ok(inf)
}

/// Control rojo de la sonda de maleabilidad (D33): un `verify` que ACEPTA cualquier
/// firma del largo correcto. `maleabilidad` DEBE cazarlo (acepta donde la referencia
/// rechaza), por la vía real de la comparación de veredictos.
pub struct VerificadorLaxo<A: AdaptadorMlDsa> {
    pub base: A,
}

impl<A: AdaptadorMlDsa> AdaptadorMlDsa for VerificadorLaxo<A> {
    fn nombre(&self) -> &str {
        "LAXO(control)"
    }
    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.base.keygen(semilla)
    }
    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        self.base.firmar(sk, msg, ctx, semilla_firma)
    }
    fn verificar(&self, _pk: &[u8], _msg: &[u8], _ctx: &[u8], sig: &[u8]) -> bool {
        !sig.is_empty() // acepta todo (la laxitud que la sonda debe cazar)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // D33 — pareja. VERDE: referencia contra sí misma, cero divergencias.
    #[test]
    fn diferencial_identico_no_divergente() {
        let casos = Caso::lote(16);
        let inf = diferencial(&Fips204_65, &Fips204_65, &casos).unwrap();
        assert!(inf.limpio(), "ref vs ref debería ser limpio: {:?}", inf.divergencias);
    }

    // D33 — pareja. ROJO: el mutante DEBE ser cazado, por la vía real (bytes + cruzada).
    #[test]
    fn diferencial_mutante_cazado() {
        let casos = Caso::lote(16);
        let mutante = Mutante { base: Fips204_65 };
        let inf = diferencial(&Fips204_65, &mutante, &casos).unwrap();
        assert!(!inf.limpio(), "el mutante NO fue detectado: el oráculo no discrimina");
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::FirmaBytes),
            "esperaba divergencia de FirmaBytes"
        );
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::VerificacionCruzada),
            "esperaba fallo de verificación cruzada"
        );
    }

    // El mutante de verdad MUTÓ (D33: comprobar que el control muerde, no es no-op).
    #[test]
    fn mutante_cambia_la_firma() {
        let c = &Caso::lote(1)[0];
        let (_, sk) = Fips204_65.keygen(&c.semilla_clave).unwrap();
        let base = Fips204_65.firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma).unwrap();
        let mut_ = Mutante { base: Fips204_65 }
            .firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)
            .unwrap();
        assert_ne!(base, mut_, "el mutante no alteró la firma");
    }

    // Conformidad de la referencia: debe salir limpia (invariantes reales).
    #[test]
    fn conformidad_referencia_limpia() {
        let casos = Caso::lote(16);
        let inf = conformidad(&Fips204_65, &casos).unwrap();
        assert!(inf.limpio(), "la referencia falló conformidad: {:?}", inf.divergencias);
    }

    // ROBUSTEZ — control positivo: la referencia DEBE rechazar toda entrada
    // malformada sin panicar (0 divergencias).
    #[test]
    fn robustez_referencia_limpia() {
        let casos = Caso::lote(16);
        let inf = robustez(&Fips204_65, &casos).unwrap();
        assert!(inf.limpio(), "la referencia no fue robusta: {:?}", inf.divergencias);
    }

    // ROBUSTEZ — control rojo (D33): el mutante que panica en verify DEBE ser cazado
    // como `Panico`, por la vía real del catch_unwind (no por el arnés).
    #[test]
    fn robustez_caza_panico() {
        let casos = Caso::lote(4);
        let inf = robustez(&PanicoMutante { base: Fips204_65 }, &casos).unwrap();
        assert!(!inf.limpio(), "robustez no cazó el pánico: la sonda no discrimina");
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::Panico),
            "esperaba una divergencia de clase Panico"
        );
    }

    // MALEABILIDAD — control positivo: la referencia contra sí misma no discrepa
    // en NINGÚN mutante (0 divergencias): un verify determinista se juzga igual.
    #[test]
    fn maleabilidad_ref_vs_ref_limpio() {
        let casos = Caso::lote(8);
        let inf = maleabilidad(&Fips204_65, &Fips204_65, &casos).unwrap();
        assert!(inf.limpio(), "ref vs ref no debería discrepar: {:?}", inf.divergencias);
    }

    // MALEABILIDAD — control rojo (D33): un verify LAXO (acepta todo) DEBE ser cazado
    // como `Maleable`, por la vía real (acepta mutantes que la referencia rechaza).
    #[test]
    fn maleabilidad_caza_laxo() {
        let casos = Caso::lote(4);
        let inf = maleabilidad(&Fips204_65, &VerificadorLaxo { base: Fips204_65 }, &casos).unwrap();
        assert!(!inf.limpio(), "no cazó el verify laxo: la sonda no discrimina");
        assert!(
            inf.divergencias.iter().any(|d| d.clase == Clase::Maleable),
            "esperaba una divergencia de clase Maleable"
        );
    }

    // Negativo por la vía real: una firma manipulada DEBE ser rechazada.
    #[test]
    fn rechaza_firma_manipulada() {
        let c = &Caso::lote(1)[0];
        let (pk, sk) = Fips204_65.keygen(&c.semilla_clave).unwrap();
        let mut sig = Fips204_65.firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma).unwrap();
        assert!(Fips204_65.verificar(&pk, &c.mensaje, &c.contexto, &sig));
        sig[100] ^= 0x01;
        assert!(!Fips204_65.verificar(&pk, &c.mensaje, &c.contexto, &sig));
    }
}
