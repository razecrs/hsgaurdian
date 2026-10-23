use crate::model::{
    Capability, CapabilityStatus, Claim, ClaimStatus, ClaimSubject, Database, Evidence,
    EvidenceKind, EvidenceLocation, EvidenceObservation, EvidenceTool, Usability,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Recover static `DirectUI` reflection property schemas and enum maps.
pub fn recover_reflection(db: &mut Database, _pe_bytes: &[u8]) {
    let (properties_map, class_property_count, mut evidence, mut claims) =
        property_observations(db);
    let inferred_bases = infer_template_bases(db);
    let mut class_records = existing_class_records(db);
    apply_property_counts(&mut class_records, class_property_count);
    apply_inferred_bases(
        &mut class_records,
        inferred_bases,
        &mut evidence,
        &mut claims,
    );
    db.properties = properties_map.into_values().flatten().collect();
    db.classes = class_records.into_values().collect();
    let property_claims = claims
        .iter()
        .filter(|claim| matches!(claim.subject, ClaimSubject::Property { .. }))
        .count();
    let base_claims = claims.len().saturating_sub(property_claims);
    db.evidence.extend(evidence);
    db.claims.extend(claims);
    db.capabilities.push(Capability {
        id: "msvc-reflection".into(),
        status: CapabilityStatus::Partial,
        analyzer: "reflection".into(),
        reason: format!(
            "{property_claims} properties observed; {base_claims} template base candidates have no proven offsets"
        ),
    });
}

type PropertyObservations = (
    BTreeMap<String, Vec<serde_json::Value>>,
    BTreeMap<String, usize>,
    Vec<Evidence>,
    Vec<Claim>,
);

fn property_observations(db: &Database) -> PropertyObservations {
    let mut properties_map: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut class_property_count: BTreeMap<String, usize> = BTreeMap::new();
    let mut evidence = Vec::new();
    let mut claims = Vec::new();
    let mut seen_property_getters = BTreeSet::new();

    // 1. Identify static PropertyInfo getter methods (e.g. Element::BackgroundProp)
    for sym in &db.symbols {
        if sym.library || !sym.sig.parse_ok {
            continue;
        }

        let method = sym.sig.method.as_deref().unwrap_or("");
        let class = sym.sig.class.as_deref().unwrap_or("Global");

        if method.ends_with("Prop") && sym.sig.storage.as_deref() == Some("static") {
            // Export and PDB streams can describe the exact same procedure.
            // Collapse only that identical getter identity; distinct overloads
            // remain separate observations and claims.
            if !seen_property_getters.insert((sym.id.as_str(), sym.rva)) {
                continue;
            }
            let prop_name = method.trim_end_matches("Prop");
            let class_name = sym
                .sig
                .namespace
                .as_deref()
                .filter(|namespace| !namespace.is_empty())
                .map_or_else(
                    || class.to_string(),
                    |namespace| format!("{namespace}::{class}"),
                );

            *class_property_count.entry(class_name.clone()).or_default() += 1;

            let prop_entry = json!({
                "class": class_name,
                "name": prop_name,
                "getter_mangled": sym.mangled,
                "vaddr": sym.vaddr,
                "provenance": "static-reflection",
            });

            properties_map
                .entry(class_name.clone())
                .or_default()
                .push(prop_entry);
            let evidence_id = format!("ev:reflection-property:{}:{:X}", sym.id, sym.rva);
            evidence.push(Evidence {
                id: evidence_id.clone(),
                kind: EvidenceKind::Reflection,
                tool: EvidenceTool::Windissect,
                rule_id: "msvc.static-property-getter".into(),
                rule_version: 1,
                location: EvidenceLocation {
                    symbol_id: Some(sym.id.clone()),
                    rva: Some(sym.rva),
                    size: Some(sym.size),
                    instruction_rvas: vec![],
                },
                observation: EvidenceObservation::ReflectionProperty {
                    owner: class_name.clone(),
                    name: prop_name.into(),
                    getter_symbol: sym.id.clone(),
                },
            });
            claims.push(Claim {
                // A property name is not a unique observation. MSVC can emit
                // overloaded or aliased static getters for the same logical
                // property, and each getter must retain its own evidence until
                // a separate corroboration pass proves they are equivalent.
                id: property_claim_id(&class_name, prop_name, &sym.id, sym.rva),
                subject: ClaimSubject::Property {
                    owner: class_name,
                    name: prop_name.into(),
                    getter_symbol: sym.id.clone(),
                },
                status: ClaimStatus::Observed,
                usability: Usability::MetadataOnly,
                evidence_ids: vec![evidence_id],
                proof_id: None,
            });
        }
    }

    (properties_map, class_property_count, evidence, claims)
}

fn infer_template_bases(db: &Database) -> BTreeMap<String, (String, String, u32)> {
    let mut inferred_bases: BTreeMap<String, (String, String, u32)> = BTreeMap::new();
    for symbol in &db.symbols {
        let Some(demangled) = symbol.demangled.as_deref() else {
            continue;
        };
        let Some(args) = template_arguments(demangled, "ClassInfo<") else {
            continue;
        };
        if args.len() < 2 {
            continue;
        }
        let derived = clean_type_name(&args[0]);
        let base = clean_type_name(&args[1]);
        if !derived.is_empty() && !base.is_empty() && derived != base {
            inferred_bases
                .entry(derived)
                .or_insert_with(|| (base, symbol.id.clone(), symbol.rva));
        }
    }

    inferred_bases
}

fn existing_class_records(db: &mut Database) -> BTreeMap<String, serde_json::Value> {
    db.classes
        .drain(..)
        .filter_map(|value| {
            value
                .get("name")?
                .as_str()
                .map(|name| (name.to_string(), value.clone()))
        })
        .collect()
}

fn apply_property_counts(
    records: &mut BTreeMap<String, serde_json::Value>,
    counts: BTreeMap<String, usize>,
) {
    for (class_name, count) in counts {
        let record = records
            .entry(class_name.clone())
            .or_insert_with(|| json!({ "name": class_name }));
        if let Some(object) = record.as_object_mut() {
            object.insert("property_count".into(), json!(count));
        }
    }
}

fn apply_inferred_bases(
    records: &mut BTreeMap<String, serde_json::Value>,
    bases: BTreeMap<String, (String, String, u32)>,
    evidence: &mut Vec<Evidence>,
    claims: &mut Vec<Claim>,
) {
    for (derived, (base, symbol_id, rva)) in bases {
        let evidence_id = format!("ev:template-base:{derived}:{base}:{rva:X}");
        evidence.push(Evidence {
            id: evidence_id.clone(),
            kind: EvidenceKind::Reflection,
            tool: EvidenceTool::Windissect,
            rule_id: "msvc.classinfo-template-base".into(),
            rule_version: 1,
            location: EvidenceLocation {
                symbol_id: Some(symbol_id.clone()),
                rva: Some(rva),
                size: None,
                instruction_rvas: vec![],
            },
            observation: EvidenceObservation::TemplateBase {
                derived: derived.clone(),
                base: base.clone(),
                symbol_id,
            },
        });
        claims.push(Claim {
            id: format!("claim:base:{derived}:{base}"),
            subject: ClaimSubject::Base {
                derived: derived.clone(),
                base: base.clone(),
                offset: None,
                is_virtual: false,
            },
            status: ClaimStatus::Candidate,
            usability: Usability::MetadataOnly,
            evidence_ids: vec![evidence_id],
            proof_id: None,
        });
        let short = derived.rsplit("::").next().unwrap_or(&derived).to_string();
        let record = records
            .entry(short.clone())
            .or_insert_with(|| json!({ "name": short }));
        if let Some(object) = record.as_object_mut() {
            object.insert("qualified_name".into(), json!(derived));
            object.entry("bases").or_insert_with(|| {
                json!([{
                    "name": base,
                    "evidence": "classinfo-template-instantiation",
                    "confidence": "likely"
                }])
            });
        }
    }
}

fn clean_type_name(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("class ")
        .trim_start_matches("struct ")
        .trim()
        .to_string()
}

fn property_claim_id(owner: &str, name: &str, getter_symbol: &str, rva: u32) -> String {
    format!("claim:property:{owner}:{name}:getter:{getter_symbol}:{rva:X}")
}

fn template_arguments(text: &str, marker: &str) -> Option<Vec<String>> {
    let start = text.find(marker)? + marker.len();
    let mut depth = 0usize;
    let mut current = String::new();
    let mut args = Vec::new();
    for ch in text[start..].chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' if depth == 0 => {
                args.push(current.trim().to_string());
                return Some(args);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_nested_classinfo_arguments() {
        let args = template_arguments(
            "void DirectUI::ClassInfo<class DirectUI::Button, class DirectUI::Element, class DirectUI::StandardCreator<class DirectUI::Button> >::Destroy()",
            "ClassInfo<",
        ).unwrap();
        assert_eq!(clean_type_name(&args[0]), "DirectUI::Button");
        assert_eq!(clean_type_name(&args[1]), "DirectUI::Element");
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn overloaded_property_getters_have_distinct_claim_ids() {
        let first = property_claim_id(
            "DirectUI::Element",
            "Content",
            "?ContentProp@Element@DirectUI@@SAPE...A",
            0x1234,
        );
        let second = property_claim_id(
            "DirectUI::Element",
            "Content",
            "?ContentProp@Element@DirectUI@@SAPE...B",
            0x5678,
        );

        assert_ne!(first, second);
        assert_eq!(
            first,
            property_claim_id(
                "DirectUI::Element",
                "Content",
                "?ContentProp@Element@DirectUI@@SAPE...A",
                0x1234,
            )
        );
    }
}
