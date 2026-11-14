// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán — oráculo adversario de implementaciones PQC de terceros.
//
//! Evidencia tipada + libro de obligaciones: nuestra disciplina de reporte (D30/D31/D33)
//! vuelta TIPO. Un hallazgo solo se reporta como `confirmado` cuando su `Afirmacion`
//! está `Cerrada`, y una afirmación solo cierra con un VERIFICADOR presente —nunca por
//! la mera ausencia de evidencia en contra—.
//!
//! El principio, en una frase: **"la ausencia de evidencia nunca reclama cierre"**
//! (D20: ante la falta de un dato, falla ruidosamente; no lo sustituyas por un defecto).
//! Por eso `Evidencia::Desconocido` es un estado EXPLÍCITO con su porqué, y NO colapsa
//! a `false`/ausente: un oráculo que no pudo mirar no es un oráculo que vio limpio.
//!
//! ## Cómo se modela una `Divergencia` del oráculo + su control rojo
//!
//! El motor diferencial afirma que DISCRIMINA cada clase de fallo. Esa afirmación nace
//! `Abierta`; solo cierra cuando el control rojo (`Mutante`/`PanicoMutante`/`VerificadorLaxo`
//! en ML-DSA, `KemErrante`/`HibridoRoto` en KEM/híbrido) es cazado por la vía real —esa es
//! la OBSERVACIÓN directa que enumera el id de la afirmación—:
//!
//! ```
//! use mohan::evidencia::{Afirmacion, Autoridad, Estado, Evidencia, Libro};
//!
//! // El oráculo afirma que discrimina la clase FirmaBytes. Nace ABIERTA: aún no probada.
//! let mut a = Afirmacion::nueva("div-FirmaBytes", "el oráculo discrimina FirmaBytes");
//! assert_eq!(a.estado, Estado::Abierta);
//!
//! // El control `Mutante` fue cazado por la vía real (comparación de bytes): esa es la
//! // observación DIRECTA que enumera el id de la afirmación (D33).
//! let verificador = Evidencia::Observacion {
//!     fuente: "diferencial(fips204, Mutante)".into(),
//!     dato: "caso 0: divergencia div-FirmaBytes (firmas deterministas distintas)".into(),
//!     autoridad: Autoridad::Directa,
//! };
//! a.cerrar_con(&verificador, Autoridad::Directa).unwrap();
//! assert_eq!(a.estado, Estado::Cerrada);
//!
//! // Solo AHORA el hallazgo se reporta como confirmado.
//! let mut libro = Libro::nuevo();
//! libro.registrar(a);
//! assert!(libro.todas_cerradas());
//! ```

/// Autoridad de una observación: qué tan DIRECTO fue lo que la produjo. El orden
/// derivado (por declaración) hace `Directa > Indirecta`, así que un verificador de
/// autoridad `Indirecta` NO cierra una afirmación abierta por una observación `Directa`.
///
/// Por qué existe (y no es un adorno): "autoridad comparable" es la guarda contra cerrar
/// un hallazgo DIRECTO (lo vio ejecutar el oráculo) con un soporte más débil (p. ej. una
/// lectura indirecta o un reporte de segunda mano). Degradar la autoridad del verificador
/// por debajo de la del hallazgo original sería exactamente el falso-cierre que D30/D31
/// prohíben: un verde anclado a menos de lo que afirma.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Autoridad {
    /// Segunda mano / derivada / reportada: NO basta para cerrar lo observado directo.
    Indirecta,
    /// El oráculo/comando la produjo ejecutando: el peldaño más alto.
    Directa,
}

/// La provenance de un dato: de DÓNDE salió y con qué fuerza probatoria. Modela los
/// cuatro orígenes que distinguimos al razonar un objetivo (D30/D31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidencia {
    /// Lo que un comando/oráculo produjo DIRECTO (una corrida, un `verify`, un diff).
    /// Es lo único que puede CERRAR una afirmación.
    Observacion {
        fuente: String,
        dato: String,
        autoridad: Autoridad,
    },
    /// Computado a partir de observaciones (guarda ids/resumen de las fuentes y la regla
    /// aplicada; no recurre sobre `Evidencia` para no crecer sin fondo).
    Derivacion { de: Vec<String>, regla: String },
    /// Razonado pero NO probado: una hipótesis con su soporte. No cierra nada.
    Inferencia { hipotesis: String, soporte: String },
    /// Desconocido EXPLÍCITO, con su porqué. NO es `false` ni ausencia (D20): un oráculo
    /// que no pudo mirar es distinto de uno que miró y vio limpio.
    Desconocido { porque: String },
}

impl Evidencia {
    /// Nombre corto de la variante, para mensajes de motivo (no confundir con el dato).
    #[must_use]
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Evidencia::Observacion { .. } => "Observacion",
            Evidencia::Derivacion { .. } => "Derivacion",
            Evidencia::Inferencia { .. } => "Inferencia",
            Evidencia::Desconocido { .. } => "Desconocido",
        }
    }
}

/// El estado de una afirmación dentro del libro de obligaciones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Estado {
    /// Planteada pero no probada: el estado de nacimiento. No se reporta como confirmada.
    Abierta,
    /// Cerrada por un verificador que la enumera y cuya autoridad es comparable.
    Cerrada,
    /// Refutada: hay evidencia de que la afirmación NO se sostiene (distinto de Abierta).
    Fallida,
}

/// Una obligación de prueba: un enunciado que empieza `Abierta` y solo pasa a `Cerrada`
/// cuando un verificador la respalda por la vía real.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Afirmacion {
    pub id: String,
    pub enunciado: String,
    pub estado: Estado,
}

impl Afirmacion {
    /// Crea una afirmación `Abierta` (el estado de nacimiento: aún no probada).
    #[must_use]
    pub fn nueva(id: impl Into<String>, enunciado: impl Into<String>) -> Afirmacion {
        Afirmacion {
            id: id.into(),
            enunciado: enunciado.into(),
            estado: Estado::Abierta,
        }
    }

    /// Cierra la afirmación SOLO si `verificador` es una `Observacion` que (a) tiene
    /// autoridad `>= autoridad_minima` (la de la observación que abrió el hallazgo, que
    /// se pasa como parámetro) y (b) ENUMERA el `id` de esta afirmación (lo contiene en
    /// su `dato` o `fuente`). En cualquier otro caso NO cierra y devuelve `Err` con el
    /// motivo, dejando el estado intacto: la ausencia de un verificador válido nunca
    /// reclama cierre (D20/D30).
    ///
    /// # Errors
    /// - El verificador no es `Evidencia::Observacion`.
    /// - Su autoridad es menor que `autoridad_minima`.
    /// - No enumera el `id` de la afirmación (o el `id` está vacío).
    pub fn cerrar_con(
        &mut self,
        verificador: &Evidencia,
        autoridad_minima: Autoridad,
    ) -> Result<(), String> {
        let (fuente, dato, autoridad) = match verificador {
            Evidencia::Observacion {
                fuente,
                dato,
                autoridad,
            } => (fuente, dato, *autoridad),
            otra => {
                return Err(format!(
                    "'{}' no cierra: el verificador es {} (solo una Observacion directa cierra; \
                     la ausencia de evidencia nunca reclama cierre)",
                    self.id,
                    otra.etiqueta(),
                ));
            }
        };

        if autoridad < autoridad_minima {
            return Err(format!(
                "'{}' no cierra: autoridad del verificador ({autoridad:?}) < requerida ({autoridad_minima:?})",
                self.id,
            ));
        }

        if self.id.is_empty() || !(dato.contains(self.id.as_str()) || fuente.contains(self.id.as_str())) {
            return Err(format!(
                "'{}' no cierra: el verificador (fuente='{fuente}') no ENUMERA el id de la afirmación",
                self.id,
            ));
        }

        self.estado = Estado::Cerrada;
        Ok(())
    }

    /// Marca la afirmación como `Fallida` (refutada). Es un estado distinto de `Abierta`:
    /// "no probada" no es "probada falsa" (D20).
    pub fn marcar_fallida(&mut self) {
        self.estado = Estado::Fallida;
    }
}

/// El libro de obligaciones: todas las afirmaciones de una corrida. Un `Informe`/hallazgo
/// se reporta como `confirmado` solo si su `Afirmacion` está `Cerrada`; mientras siga
/// `Abierta`, el hallazgo es un candidato, no un confirmado.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Libro {
    pub afirmaciones: Vec<Afirmacion>,
}

impl Libro {
    #[must_use]
    pub fn nuevo() -> Libro {
        Libro {
            afirmaciones: Vec::new(),
        }
    }

    /// Añade una afirmación al libro.
    pub fn registrar(&mut self, a: Afirmacion) {
        self.afirmaciones.push(a);
    }

    /// Cuántas afirmaciones siguen `Abierta` (sin verificador que las cierre).
    #[must_use]
    pub fn abiertas(&self) -> usize {
        self.afirmaciones
            .iter()
            .filter(|a| a.estado == Estado::Abierta)
            .count()
    }

    /// `true` solo si hay al menos una afirmación y TODAS están `Cerrada`. Un libro
    /// vacío devuelve `false` a propósito: "nada que probar" no es "todo probado"
    /// (D30 — un verde vacío es indistinguible de uno que no midió nada).
    #[must_use]
    pub fn todas_cerradas(&self) -> bool {
        !self.afirmaciones.is_empty()
            && self.afirmaciones.iter().all(|a| a.estado == Estado::Cerrada)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // D33 — control positivo: una afirmación nueva no se auto-confirma.
    #[test]
    fn afirmacion_sin_verificador_queda_abierta() {
        let a = Afirmacion::nueva("A-1", "el oráculo discrimina FirmaBytes");
        assert_eq!(a.estado, Estado::Abierta);

        let mut libro = Libro::nuevo();
        libro.registrar(a);
        assert_eq!(libro.abiertas(), 1);
        assert!(
            !libro.todas_cerradas(),
            "una afirmación sin verificador NO puede reclamar cierre"
        );
    }

    // D33 — rojo: un verificador que no nombra el id no cierra, por la vía real
    // (la comprobación de enumeración), y el estado se queda intacto.
    #[test]
    fn verificador_que_no_enumera_el_id_no_cierra() {
        let mut a = Afirmacion::nueva("A-1", "algo");
        let verificador = Evidencia::Observacion {
            fuente: "otra-corrida".into(),
            dato: "divergencia en el caso 3 (clase distinta)".into(), // no menciona "A-1"
            autoridad: Autoridad::Directa,
        };
        let r = a.cerrar_con(&verificador, Autoridad::Indirecta);
        assert!(r.is_err(), "no debe cerrar si el verificador no enumera el id");
        assert!(r.unwrap_err().contains("no ENUMERA"));
        assert_eq!(a.estado, Estado::Abierta, "el estado debe quedar intacto");
    }

    // D33 — rojo: autoridad insuficiente no cierra (la guarda de "autoridad comparable").
    #[test]
    fn verificador_de_autoridad_menor_no_cierra() {
        let mut a = Afirmacion::nueva("A-1", "algo");
        let verificador = Evidencia::Observacion {
            fuente: "reporte-indirecto".into(),
            dato: "A-1 confirmada de oídas".into(), // SÍ enumera el id...
            autoridad: Autoridad::Indirecta,        // ...pero su autoridad es menor
        };
        let r = a.cerrar_con(&verificador, Autoridad::Directa);
        assert!(r.is_err(), "autoridad Indirecta < Directa no debe cerrar");
        assert!(r.unwrap_err().contains("autoridad"));
        assert_eq!(a.estado, Estado::Abierta);
    }

    // D33 — verde: observación directa que enumera el id y con autoridad suficiente SÍ cierra.
    #[test]
    fn verificador_valido_cierra() {
        let mut a = Afirmacion::nueva("A-1", "el oráculo discrimina FirmaBytes");
        let verificador = Evidencia::Observacion {
            fuente: "diferencial(fips204, Mutante)".into(),
            dato: "caso 0: divergencia A-1 (firmas deterministas distintas)".into(),
            autoridad: Autoridad::Directa,
        };
        a.cerrar_con(&verificador, Autoridad::Directa)
            .expect("la observación válida debía cerrar");
        assert_eq!(a.estado, Estado::Cerrada);

        let mut libro = Libro::nuevo();
        libro.registrar(a);
        assert_eq!(libro.abiertas(), 0);
        assert!(libro.todas_cerradas());
    }

    // D20/D33 — Desconocido es un estado EXPLÍCITO: ni cierra (no es Observacion) ni
    // colapsa a `false`/ausente (la afirmación sigue Abierta, no pasa a Fallida).
    #[test]
    fn desconocido_no_es_ausencia() {
        let desc = Evidencia::Desconocido {
            porque: "la impl del objetivo no expuso la operación bajo prueba".into(),
        };

        // Es su propia variante, con su porqué: no es ausencia de evidencia.
        match &desc {
            Evidencia::Desconocido { porque } => assert!(!porque.is_empty()),
            otra => panic!("debería ser Desconocido, no {}", otra.etiqueta()),
        }

        // No cierra: un desconocido no es un verificador.
        let mut a = Afirmacion::nueva("A-1", "algo");
        let r = a.cerrar_con(&desc, Autoridad::Indirecta);
        assert!(r.is_err(), "Desconocido no debe cerrar una afirmación");

        // Y NO es `false`/refutado: la afirmación sigue Abierta, no Fallida.
        assert_eq!(
            a.estado,
            Estado::Abierta,
            "un desconocido no refuta: no colapsa a Fallida ni a ausente"
        );
    }
}
