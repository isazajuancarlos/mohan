// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán.
//
// Adaptadores de implementaciones de TERCEROS bajo diferencial. Cada uno enchufa
// una impl externa a `AdaptadorMlDsa` operando sobre bytes serializados, SIN tocar
// el motor del oráculo.

use crate::AdaptadorMlDsa;

// Trait y tipos de la impl de tercero. Vive en su propio módulo porque su trait
// `KeyGen` colisiona de nombre con el de `fips204` que usa el lib raíz; aquí solo
// entra el de ml-dsa-rs.
use mldsa_isomoes::{EncodedVerifyingKey, KeyGen, MlDsa65, Seed, Signature, VerifyingKey};

/// Objetivo 1: `isomoes/ml-dsa-rs` @ `e7d4379` (ML-DSA-65). Reimplementación
/// independiente "basada en la estructura de RustCrypto ML-DSA" (su README), NO un
/// fork → el código es propio y puede divergir: ahí vive el posible hallazgo.
///
/// `sk` serializado = la **semilla de 32 B** (handle interno de este adaptador): la
/// impl deriva la clave con `from_seed` de forma determinista, así que la semilla
/// basta y no hace falta el `skEncode` FIPS que ml-dsa-rs no expone. mohán compara
/// `pk` y `firma` entre impl, nunca el `sk` (cada adaptador usa el suyo).
pub struct MlDsaRs65;

impl MlDsaRs65 {
    /// Construye el M′ de FIPS-204 §Algoritmo 2 para la variante pura (sin prehash):
    /// `M′ = IntegerToBytes(0,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ M`. Debe calcarse
    /// byte-a-byte al de la referencia o la firma diverge por el ARNÉS, no por la impl.
    fn firmar_con_rnd(sk: &[u8], msg: &[u8], ctx: &[u8], rnd: &[u8; 32]) -> Result<Vec<u8>, String> {
        if ctx.len() > 255 {
            return Err(format!("ctx de {} B > 255", ctx.len()));
        }
        let semilla: [u8; 32] = sk
            .try_into()
            .map_err(|_| format!("sk (semilla) con largo {} != 32", sk.len()))?;
        let kp = MlDsa65::from_seed(&semilla.into());
        let rnd_b: Seed = (*rnd).into();
        let prefijo = [0u8, ctx.len() as u8];
        let m_prima: [&[u8]; 3] = [&prefijo, ctx, msg];
        let sig = kp.signing_key().sign_internal(&m_prima, &rnd_b);
        Ok(sig.encode().to_vec())
    }
}

impl AdaptadorMlDsa for MlDsaRs65 {
    fn nombre(&self) -> &str {
        "ml-dsa-rs/isomoes@e7d4379"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kp = MlDsa65::from_seed(&(*semilla).into());
        let pk = kp.verifying_key().encode().to_vec();
        // El `sk` serializado de este adaptador es la propia semilla (handle).
        Ok((pk, semilla.to_vec()))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        // Honra el `rnd` general de mohán: la firma usa `rnd = semilla_firma` igual
        // que `try_sign_with_seed` de la referencia (verificado: su `DummyRng` copia
        // la semilla directa como `rnd`).
        Self::firmar_con_rnd(sk, msg, ctx, semilla_firma)
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let Ok(enc_pk) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
            return false;
        };
        let Ok(firma) = Signature::<MlDsa65>::try_from(sig) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_pk);
        vk.verify_with_context(msg, ctx, &firma)
    }
}

/// Objetivo 2: `QuantumDrizzy/Bastion` @ `052496028` (ML-DSA-65). From-scratch
/// sobre un **Keccak escrito a mano** (mayor probabilidad de divergencia que un
/// reimpl modelado en RustCrypto) y con **SECURITY.md** (canal de divulgación
/// limpio). API byte-native: `keygen_internal`/`sign_internal`/`verify` operan
/// directo sobre los bytes FIPS, así que el adaptador es casi transparente.
pub struct Bastion65;

impl AdaptadorMlDsa for Bastion65 {
    fn nombre(&self) -> &str {
        "bastion/QuantumDrizzy@052496028"
    }

    fn keygen(&self, semilla: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
        // keygen_internal es la KeyGen_internal de FIPS-204 desde ξ; devuelve (pk, sk) FIPS.
        Ok(bastion::sig::mldsa::keygen_internal(semilla))
    }

    fn firmar(
        &self,
        sk: &[u8],
        msg: &[u8],
        ctx: &[u8],
        semilla_firma: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if ctx.len() > 255 {
            return Err(format!("ctx de {} B > 255", ctx.len()));
        }
        // Mismo M′ que la referencia y que el objetivo 1 (formateo ya validado por el
        // control positivo de ml-dsa-rs): [0,|ctx|] ‖ ctx ‖ M. rnd = semilla_firma.
        let mut m_prima = Vec::with_capacity(2 + ctx.len() + msg.len());
        m_prima.push(0u8);
        m_prima.push(ctx.len() as u8);
        m_prima.extend_from_slice(ctx);
        m_prima.extend_from_slice(msg);
        bastion::sig::mldsa::sign_internal(sk, &m_prima, semilla_firma)
            .ok_or_else(|| "sign_internal devolvió None".to_string())
    }

    fn verificar(&self, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        bastion::sig::mldsa::verify(pk, msg, sig, ctx)
    }
}

#[cfg(test)]
mod pruebas {
    use super::{Bastion65, MlDsaRs65};
    use crate::{AdaptadorMlDsa, Caso, Fips204_65};

    // Control de cableado del objetivo 2: round-trip propio por la vía real.
    #[test]
    fn bastion_round_trip_propio() {
        for c in Caso::lote(4) {
            let (pk, sk) = Bastion65.keygen(&c.semilla_clave).unwrap();
            let sig = Bastion65
                .firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)
                .unwrap();
            assert!(
                Bastion65.verificar(&pk, &c.mensaje, &c.contexto, &sig),
                "bastion no verifica su propia firma"
            );
        }
    }

    // Control positivo 1: la clave pública del tercero DEBE byte-igualar la de la
    // referencia para la misma semilla (conformidad de keygen + encoding de pk).
    #[test]
    fn pk_conforme_con_referencia() {
        for c in Caso::lote(4) {
            let (pk_ref, _) = Fips204_65.keygen(&c.semilla_clave).unwrap();
            let (pk_ter, _) = MlDsaRs65.keygen(&c.semilla_clave).unwrap();
            assert_eq!(pk_ref, pk_ter, "pk diverge en keygen para la misma semilla");
        }
    }

    // Control positivo 2 (D33, valida el ARNÉS): con rnd=0 la firma del adaptador
    // —vía `sign_internal` con M′ formateado a mano— DEBE byte-igualar la firma
    // determinista de la referencia. Si pasa, el formateo de M′ es correcto y
    // cualquier divergencia con rnd≠0 es del OBJETIVO, no de mi formateo.
    #[test]
    fn firma_rnd_cero_byte_igual_a_referencia() {
        let cero = [0u8; 32];
        for c in Caso::lote(4) {
            let (_, sk_ref) = Fips204_65.keygen(&c.semilla_clave).unwrap();
            let (_, sk_ter) = MlDsaRs65.keygen(&c.semilla_clave).unwrap();
            let s_ref = Fips204_65.firmar(&sk_ref, &c.mensaje, &c.contexto, &cero).unwrap();
            let s_ter = MlDsaRs65.firmar(&sk_ter, &c.mensaje, &c.contexto, &cero).unwrap();
            assert_eq!(s_ref, s_ter, "firma rnd=0 diverge: M′ mal formateado o impl no conforme");
        }
    }

    // Round-trip propio por la vía real (firma con rnd≠0 del lote, se verifica sola).
    #[test]
    fn round_trip_propio() {
        for c in Caso::lote(4) {
            let (pk, sk) = MlDsaRs65.keygen(&c.semilla_clave).unwrap();
            let sig = MlDsaRs65
                .firmar(&sk, &c.mensaje, &c.contexto, &c.semilla_firma)
                .unwrap();
            assert!(
                MlDsaRs65.verificar(&pk, &c.mensaje, &c.contexto, &sig),
                "el tercero no verifica su propia firma"
            );
        }
    }
}
