// SPDX-License-Identifier: LicenseRef-Propietario
// Autor: Juan Carlos Isaza. Proyecto: Mohán — CLI del oráculo PQC.

use mohan::aead::{diferencial_aead, CasoAead, EasylockAesGcm, EasylockChaChaPoly, RefAesGcm, RefChaChaPoly};
use mohan::hibrido::{binding_hibrido, CasoHibrido, HibridoRoto, XWing768};
use mohan::kem::{diferencial_kem, seguridad_kem, BastionKem768, CasoKem, Fips203_768};
use mohan::{conformidad, diferencial, maleabilidad, robustez, Bastion65, Caso, Fips204_65, Fips204_87, Informe, MlDsaRs65, QrlGo87, QrlRust87};
use std::process::ExitCode;

fn ayuda() {
    eprintln!(
        "Mohán — oráculo adversario de implementaciones PQC de terceros (v0: ML-DSA/FIPS 204).\n\
         \n\
         USO:\n\
           mohan conf  [iters]   conformidad de la implementación de referencia (fips204)\n\
           mohan diff  [iters]   diferencial referencia-vs-referencia (control: debe salir LIMPIO)\n\
           mohan demo  [iters]   diferencial referencia-vs-MUTANTE (debe HALLAR divergencias)\n\
           mohan ml-dsa-rs [iters]  diferencial fips204 vs isomoes/ml-dsa-rs (OBJETIVO 1)\n\
           mohan conf-ter  [iters]  conformidad del tercero ml-dsa-rs a solas\n\
           mohan robustez-ter [iters] robustez del tercero a entradas malformadas (pánico=DoS)\n\
           mohan robustez [iters]     robustez de la referencia (control: LIMPIO)\n\
           mohan bastion [iters]      diferencial fips204 vs Bastion (OBJETIVO 2, Keccak propio)\n\
           mohan conf-bastion [iters] conformidad de Bastion a solas\n\
           mohan rob-bastion [iters]  robustez de Bastion a entradas malformadas\n\
           mohan malea-ter [iters]    maleabilidad: fips204 vs ml-dsa-rs (firmas no-canónicas)\n\
           mohan malea-bastion [it]   maleabilidad: fips204 vs Bastion\n\
           mohan kem-seg-bastion [it] ML-KEM: rechazo implicito/robustez de Bastion (JOYA CCA)\n\
           mohan kem-diff-bastion [it] ML-KEM: diferencial fips203 vs Bastion\n\
           mohan kem-seg [it]         ML-KEM: seguridad de la referencia (control)\n\
           mohan hib-xwing [it]       HÍBRIDO: binding de x-wing-rust (X25519+ML-KEM)\n\
           mohan hib-roto [it]        HÍBRIDO: control rojo non-binding (debe HALLAR)\n\
           mohan aead-cc [it]         AEAD: diferencial easylock ChaCha20-Poly1305 vs ref\n\
           mohan aead-gcm [it]        AEAD: diferencial easylock AES-256-GCM vs ref\n\
         \n\
         Sale con codigo 1 si hay divergencias. El tercero bajo prueba se enchufa\n\
         como un AdaptadorMlDsa nuevo; este binario v0 corre la referencia y el control."
    );
}

fn imprime(inf: &Informe, titulo: &str) {
    println!("== {titulo} ==");
    println!("casos: {}", inf.casos);
    if inf.limpio() {
        println!("resultado: LIMPIO (0 divergencias)");
    } else {
        println!("resultado: {} DIVERGENCIAS", inf.divergencias.len());
        for d in &inf.divergencias {
            println!("  [caso {}] {:?}: {}", d.caso, d.clase, d.detalle);
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("diff");
    let iters: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
    if cmd.starts_with("aead") {
        let casos = CasoAead::lote(iters);
        let inf = match cmd {
            "aead-cc" => diferencial_aead(&RefChaChaPoly, &EasylockChaChaPoly, &casos),
            "aead-gcm" => diferencial_aead(&RefAesGcm, &EasylockAesGcm, &casos),
            _ => { ayuda(); return ExitCode::from(2); }
        };
        return match inf {
            Ok(inf) => { imprime(&inf, cmd); if inf.limpio() { ExitCode::SUCCESS } else { ExitCode::from(1) } }
            Err(e) => { eprintln!("error: {e}"); ExitCode::from(3) }
        };
    }

    if cmd.starts_with("hib") {
        let casos = CasoHibrido::lote(iters);
        let inf = match cmd {
            "hib-xwing" => binding_hibrido(&XWing768, &casos),
            "hib-roto" => binding_hibrido(&HibridoRoto, &casos),
            _ => {
                ayuda();
                return ExitCode::from(2);
            }
        };
        return match inf {
            Ok(inf) => {
                imprime(&inf, cmd);
                if inf.limpio() { ExitCode::SUCCESS } else { ExitCode::from(1) }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(3)
            }
        };
    }

    if cmd.starts_with("kem") {
        let casos = CasoKem::lote(iters);
        let inf = match cmd {
            "kem-seg-bastion" => seguridad_kem(&BastionKem768, &casos),
            "kem-diff-bastion" => diferencial_kem(&Fips203_768, &BastionKem768, &casos),
            "kem-seg" => seguridad_kem(&Fips203_768, &casos),
            _ => {
                ayuda();
                return ExitCode::from(2);
            }
        };
        return match inf {
            Ok(inf) => {
                imprime(&inf, cmd);
                if inf.limpio() { ExitCode::SUCCESS } else { ExitCode::from(1) }
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(3)
            }
        };
    }

    let casos = Caso::lote(iters);

    let inf = match cmd {
        "conf" => conformidad(&Fips204_65, &casos),
        "diff" => diferencial(&Fips204_65, &Fips204_65, &casos),
        "demo" => diferencial(&Fips204_65, &mohan::Mutante { base: Fips204_65 }, &casos),
        "ml-dsa-rs" => diferencial(&Fips204_65, &MlDsaRs65, &casos),
        "conf-ter" => conformidad(&MlDsaRs65, &casos),
        "robustez-ter" => robustez(&MlDsaRs65, &casos),
        "robustez" => robustez(&Fips204_65, &casos),
        "bastion" => diferencial(&Fips204_65, &Bastion65, &casos),
        "conf-bastion" => conformidad(&Bastion65, &casos),
        "rob-bastion" => robustez(&Bastion65, &casos),
        "malea-ter" => maleabilidad(&Fips204_65, &MlDsaRs65, &casos),
        "malea-bastion" => maleabilidad(&Fips204_65, &Bastion65, &casos),
        // OBJETIVO 5 (QRL/Zond) — HILO 3, nivel ML-DSA-87:
        "qrl-87-ctrl" => diferencial(&Fips204_87, &Fips204_87, &casos), // control: LIMPIO
        "qrl-rust" => diferencial(&Fips204_87, &QrlRust87, &casos), // keygen+firma+verify cruzado
        "qrl-rust-demo" => diferencial(&Fips204_87, &mohan::Mutante { base: QrlRust87 }, &casos), // D33: DEBE hallar
        "qrl-rust-conf" => conformidad(&QrlRust87, &casos),
        "qrl-rust-malea" => maleabilidad(&Fips204_87, &QrlRust87, &casos), // firmas no-canónicas
        "qrl-rust-rob" => robustez(&QrlRust87, &casos), // pánico/DoS con bytes malformados
        // go-qrllib = la impl que corre en el NODO Zond (consenso):
        "qrl-go" => diferencial(&Fips204_87, &QrlGo87, &casos), // go vs referencia
        "qrl-go-conf" => conformidad(&QrlGo87, &casos),
        "qrl-go-malea" => maleabilidad(&Fips204_87, &QrlGo87, &casos),
        "qrl-go-rob" => robustez(&QrlGo87, &casos),
        "qrl-go-demo" => diferencial(&Fips204_87, &mohan::Mutante { base: QrlGo87 }, &casos), // D33
        "qrl-cross" => diferencial(&QrlRust87, &QrlGo87, &casos), // las DOS impl del nodo, cara a cara
        // D33: control de la MALEABILIDAD a nivel 87 — un verify LAXO DEBE ser cazado
        // (prueba que las mutaciones SON no-canónicas y que la sonda discrimina):
        "qrl-malea-laxo" => maleabilidad(&Fips204_87, &mohan::VerificadorLaxo { base: Fips204_87 }, &casos),
        _ => {
            ayuda();
            return ExitCode::from(2);
        }
    };

    match inf {
        Ok(inf) => {
            imprime(&inf, cmd);
            if inf.limpio() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(3)
        }
    }
}
