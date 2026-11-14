<!-- SPDX-License-Identifier: LicenseRef-Propietario -->
<!-- Autor/titular: Juan Carlos Isaza. Configuración general: ~/.claude/CLAUDE.md -->

# Mohán — oráculo adversario de implementaciones PQC de terceros

> Nombre provisional (el espíritu de las aguas del folclor colombiano que acecha,
> prueba y engaña al que pasa). Juan lo confirma.

**Qué es.** El motor de una clase de caza nueva: encontrar bugs en las
implementaciones **post-cuánticas de TERCEROS** que la ola de migración 2026 está
desplegando a las carreras —ML-DSA/ML-KEM, híbridos— para divulgarlos por canal
oficial (CVE/GHSA/VRP del proveedor). La capa de **firma** (ML-DSA/FIPS 204) va
años por detrás del KEM en madurez: ahí empieza.

**Por qué es nuestro foso.** Combina lo que casi nadie tiene junto: implementación
PQC conformante propia (quipu), arnés diferencial/adversarial demostrado (familia
Iraca) y Claude-en-el-loop. Precedente que valida el método: en jul-2026 un modelo
de Anthropic halló un fallo en HAWK y el equipo lo retiró de la competencia NIST.

**Qué lo distingue de Iraca-2/3/4** (que ya diferencian crates PQC): Iraca verifica
las dependencias de **quipu** (acreditación EF-PQ). Mohán apunta el mismo método
**hacia afuera**, a impl de terceros desplegadas, y abstrae el objetivo tras un
`AdaptadorMlDsa` que opera sobre **bytes serializados** — así un crate, un
subproceso CLI o una FFI se enchufan sin tocar el motor.

## El método

Se conduce a cada implementación con la MISMA entrada determinista (semillas fijas)
y se exige igualdad **byte-a-byte**. Una divergencia en cualquier capa es un hallazgo:

- **Diferencial** (`diferencial`): dos impl, misma semilla → misma clave pública,
  misma firma determinista, verificación cruzada en ambos sentidos.
- **Conformidad** (`conformidad`): invariantes que una sola impl conforme DEBE
  cumplir — determinismo, round-trip, y **rechazo** de firma/mensaje/contexto
  manipulados.

El control de discriminación es un **mutante** (`Mutante`) que corrompe un byte de
cada firma: el banco exige que el oráculo lo CACE por la vía real (D33).

## Uso

```
cargo run -- conf  [iters]   # conformidad de la referencia (fips204)
cargo run -- diff  [iters]   # diferencial ref-vs-ref (control: LIMPIO)
cargo run -- demo  [iters]   # diferencial ref-vs-MUTANTE (debe HALLAR)
```

Sale con código 1 si hay divergencias.

## Verde local (el del CI, protocolo solo-local)

```
cargo test
cargo clippy --all-targets -- -D warnings
```

## Estado (v0, 2026-10-13)

- ML-DSA-65 (FIPS 204) vía adaptador de referencia `fips204`.
- 5 pruebas verdes, clippy `-D warnings` limpio, binario corre los tres modos.
- **Pendiente**: enchufar el PRIMER objetivo de tercero real (recon de selección:
  impl PQC joven, en despliegue, con canal de seguridad, NO sobre-auditada);
  ML-KEM/FIPS 203 e híbrido (binding/downgrade); vectores ACVP/KAT del NIST;
  sonda de no-tiempo-constante; manejo de aleatoriedad en ML-DSA (fuga de 1 bit).
