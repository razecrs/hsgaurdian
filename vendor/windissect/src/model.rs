//! Target-independent intermediate representation consumed by every emitter.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where a fact came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    PeExport,
    PeUnwind,
    PeUnwindHandler,
    PeGuardCf,
    PeCallTarget,
    PeTailTarget,
    PeSafeSeh,
    PeEntryPoint,
    Pdb,
    Demangler,
    R2Infer,
    Reflection,
    Human,
}

/// Confidence assigned to an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Certain,
    Likely,
    Tentative,
}

/// How far a symbol has been worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    Auto,
    Templated,
    HumanVerified,
    EmuTested,
}

/// Shape classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Ctor,
    Dtor,
    Refcount,
    Accessor,
    Thunk,
    Method,
    CFunc,
    Operator,
    Data,
    Unknown,
}

/// A structured C++ type; the display text is kept alongside in [`TypeText`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "kebab-case")]
pub enum Type {
    Builtin {
        name: String,
    },
    Named {
        path: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<TypeArg>,
    },
    Ptr {
        to: Box<Self>,
    },
    Ref {
        to: Box<Self>,
    },
    Const {
        of: Box<Self>,
    },
    FnPtr {
        ret: Box<Self>,
        params: Vec<Self>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        callconv: Option<String>,
    },
    /// Parse gap, kept verbatim.
    Raw {
        text: String,
    },
}

/// A template argument: a type or a non-type constant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TypeArg {
    Type(Type),
    Const(i64),
    Raw(String),
}

/// A type as structured AST plus its display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeText {
    pub text: String,
    pub ast: Type,
}

/// Structured signature. `parse_ok=false` means it was not fully structured.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Signature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>, // public | protected | private
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>, // static | virtual
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callconv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ret: Option<TypeText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    pub params: Vec<TypeText>,
    #[serde(default)]
    pub is_const: bool,
    pub parse_ok: bool,
}

/// One exported or internal function/data symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Stable id across versions (the mangled name, never the address).
    pub id: String,
    pub mangled: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    pub vaddr: u64,
    /// Relative virtual address within the image.
    #[serde(default)]
    pub rva: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(default)]
    pub size: u32,
    /// Exact procedure length supplied by debug information, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_size: Option<u32>,
    /// True when the symbol is known to describe executable code.
    #[serde(default)]
    pub is_code: bool,
    /// PE forwarded-export target, when this is not code in the current image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<String>,
    /// Reloc-normalized body hash for impl-change diffing; empty until disasm.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub body_hash: String,
    pub exported: bool,
    /// CRT/STL/ETW boilerplate, not dui70's own.
    #[serde(default)]
    pub library: bool,
    pub kind: Kind,
    pub coverage: Coverage,
    pub provenance: Provenance,
    pub confidence: Confidence,
    pub sig: Signature,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
}

/// A declaration imported from a comparison corpus. Candidates are retained
/// separately from symbols so reference material cannot become callable IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceCandidate {
    pub id: String,
    pub class: String,
    pub method: String,
    pub signature: String,
    pub parameter_count: usize,
    pub source_file: String,
    pub source_line: usize,
    pub evidence_kind: String,
    #[serde(default)]
    pub matched_symbol_ids: Vec<String>,
}

/// A discrepancy-driven recovery task. External declarations can create a job,
/// but only Windissect evidence and passing proofs can move it to `Verified`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJob {
    pub id: String,
    pub candidate_id: String,
    pub kind: RecoveryJobKind,
    pub state: RecoveryJobState,
    pub class: String,
    pub method: String,
    pub expected_signature: String,
    #[serde(default)]
    pub matched_symbol_ids: Vec<String>,
    #[serde(default)]
    pub evidence_requirements: Vec<RecoveryRequirement>,
    #[serde(default)]
    pub satisfied_claim_ids: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryJobKind {
    MissingDeclaration,
    DeclarationOnly,
    InlineDeclaration,
    PureVirtualDeclaration,
    SpecialMember,
    StubDeclaration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryJobState {
    Unresolved,
    Candidate,
    Verified,
    Withheld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryRequirement {
    SymbolIdentity,
    ExactSignature,
    Addressability,
    CallingConvention,
    ExecutableMapping,
    TypeOrCallsiteEvidence,
    VtableSlot,
}

/// Identity of the exact binary an IR was built from (version-diff anchor).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdb_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb_age: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_base: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size: Option<u64>,
    /// Modules this binary imports from, as named in its import directory.
    ///
    /// Module-level dependencies, not the per-symbol `imports` on a Symbol.
    /// The PE parser already holds these; not recording them meant anyone
    /// wanting a dependency graph had to shell out to objdump for data the
    /// extractor had in hand.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
}

/// A stable reference to bytes/instructions supporting an analysis fact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rva: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instruction_rvas: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    PeMetadata,
    PdbRecord,
    Instruction,
    Dataflow,
    Rtti,
    Reflection,
    Relocation,
    Unwind,
    Manual,
    OracleImport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceTool {
    Windissect,
    Ida,
    Radare2,
    Pdb,
    PeLoader,
    Human,
    Other,
}

/// One immutable observation. Evidence never directly means a declaration is
/// safe: claims cite evidence and proofs decide usability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub kind: EvidenceKind,
    pub tool: EvidenceTool,
    pub rule_id: String,
    pub rule_version: u32,
    pub location: EvidenceLocation,
    pub observation: EvidenceObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EvidenceObservation {
    MemberAccess {
        owner: String,
        offset: u64,
        width: u32,
        access: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        suggested_name: Option<String>,
    },
    AllocationVtable {
        owner: String,
        size: u64,
        vftable: u64,
    },
    AllocationConstructor {
        owner: String,
        size: u64,
        constructor: u64,
    },
    ReflectionProperty {
        owner: String,
        name: String,
        getter_symbol: String,
    },
    TemplateBase {
        derived: String,
        base: String,
        symbol_id: String,
    },
    Text {
        text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStatus {
    Observed,
    Derived,
    Corroborated,
    Candidate,
    Rejected,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Usability {
    Verified,
    #[default]
    MetadataOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ClaimSubject {
    Member {
        owner: String,
        offset: u64,
        width: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bit_offset: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bit_size: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        type_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Proven object-relative storage that is not necessarily a distinct
        /// source-level C++ member declaration.
        #[serde(default)]
        structural_only: bool,
        access: String,
    },
    ObjectSize {
        owner: String,
        size: u64,
    },
    Signature {
        symbol_id: String,
        signature: Signature,
    },
    Base {
        derived: String,
        base: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        is_virtual: bool,
    },
    Property {
        owner: String,
        name: String,
        getter_symbol: String,
    },
    VtableSlot {
        owner: String,
        table_rva: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        table_object_offset: Option<i64>,
        slot: u32,
        target_rva: u32,
    },
    EnumValue {
        owner: String,
        name: String,
        value: i64,
    },
    Callable {
        symbol_id: String,
        rva: u32,
    },
    Text {
        category: String,
        text: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub subject: ClaimSubject,
    pub status: ClaimStatus,
    #[serde(default)]
    pub usability: Usability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofObligation {
    pub name: String,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub id: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub passed: bool,
    pub obligations: Vec<ProofObligation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conflict {
    pub id: String,
    pub claim_ids: Vec<String>,
    pub reason: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityStatus {
    Supported,
    Partial,
    Unsupported,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub id: String,
    pub status: CapabilityStatus,
    pub analyzer: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionRecord {
    pub rva: u32,
    pub length: u8,
    pub bytes: String,
    pub mnemonic: String,
    pub text: String,
    pub flow: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_target_rva: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_target_rva: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    pub from_rva: u32,
    pub to_rva: u32,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAnalysis {
    pub rva: u32,
    pub size: u32,
    pub symbol_ids: Vec<String>,
    pub instructions: Vec<InstructionRecord>,
    pub cfg_edges: Vec<ControlFlowEdge>,
}

/// Proof-gated, emitter-ready semantic view derived from the observation graph.
/// The proof graph remains authoritative; these records only index claims in a
/// form that C++/Rust emitters can consume deterministically.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticModel {
    #[serde(default)]
    pub classes: Vec<SemanticClass>,
    #[serde(default)]
    pub enums: Vec<SemanticEnum>,
    #[serde(default)]
    pub aliases: Vec<SemanticAlias>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SemanticStatus {
    Verified,
    Candidate,
    Withheld,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticClass {
    pub qualified_name: String,
    #[serde(default = "default_semantic_kind")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u32>,
    pub status: SemanticStatus,
    #[serde(default)]
    pub fields: Vec<SemanticField>,
    #[serde(default)]
    pub bases: Vec<SemanticBase>,
    #[serde(default)]
    pub vtables: Vec<SemanticVtable>,
    #[serde(default)]
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticField {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub offset: u64,
    pub width: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_size: Option<u8>,
    #[serde(default)]
    pub structural_only: bool,
    pub status: SemanticStatus,
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticBase {
    pub qualified_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    pub is_virtual: bool,
    pub status: SemanticStatus,
    #[serde(default)]
    pub relationship_verified: bool,
    #[serde(default)]
    pub offset_verified: bool,
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticVtable {
    pub rva: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_offset: Option<i64>,
    pub status: SemanticStatus,
    #[serde(default)]
    pub slots: Vec<SemanticVtableSlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticVtableSlot {
    pub slot: u32,
    pub target_rva: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub this_adjustment: Option<i32>,
    pub status: SemanticStatus,
    pub claim_ids: Vec<String>,
}

fn default_semantic_kind() -> String {
    "class".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticEnum {
    pub qualified_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub underlying_type: Option<String>,
    pub status: SemanticStatus,
    pub values: Vec<SemanticEnumValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticEnumValue {
    pub name: String,
    pub value: i64,
    pub status: SemanticStatus,
    pub claim_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticAlias {
    pub name: String,
    pub target: String,
    pub status: SemanticStatus,
    pub claim_ids: Vec<String>,
}

/// The serialized IR. Reserved sections are shaped now for later passes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Database {
    pub schema: u32,
    pub generated: String,
    pub tool: String,
    pub binary: BinaryInfo,
    pub symbols: Vec<Symbol>,
    /// Diagnostics for PDB/RTTI type recovery. This explicitly distinguishes a
    /// stripped PDB from a successful recovery that happened to find no UDTs.
    #[serde(default)]
    pub type_recovery: serde_json::Value,
    #[serde(default)]
    pub types: Vec<serde_json::Value>,
    #[serde(default)]
    pub vtables: Vec<serde_json::Value>,
    #[serde(default)]
    pub classes: Vec<serde_json::Value>,
    #[serde(default)]
    pub enums: Vec<serde_json::Value>,
    #[serde(default)]
    pub properties: Vec<serde_json::Value>,
    /// Schema-v2 proof graph. Legacy flattened sections above remain readable
    /// during migration, but verified emitters must consume these records.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
    #[serde(default)]
    pub conflicts: Vec<Conflict>,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
    #[serde(default)]
    pub functions: Vec<FunctionAnalysis>,
    /// Schema-v3 typed semantic projection. Facts remain proof-gated by their
    /// referenced claim IDs and never become verified through migration.
    #[serde(default)]
    pub semantic: SemanticModel,
    /// Reference-corpus declarations retained as non-callable candidates.
    #[serde(default)]
    pub reference_candidates: Vec<ReferenceCandidate>,
    /// Refine-mode work queue derived from comparison discrepancies. Jobs are
    /// safe to persist because their verification state is recomputed solely
    /// from the IR proof graph.
    #[serde(default)]
    pub recovery_jobs: Vec<RecoveryJob>,
    /// Lossless-ish inventory of PDB symbol-stream records not yet projected
    /// into a dedicated typed section. Records retain module, kind, name, and
    /// address/size when the PDB exposes them.
    #[serde(default)]
    pub pdb_records: Vec<serde_json::Value>,
}

impl Database {
    /// Index every claim that currently satisfies the proof graph. Bulk
    /// consumers should build this once instead of repeatedly rescanning all
    /// evidence, proofs, and conflicts.
    pub fn proven_claim_ids(&self) -> BTreeSet<&str> {
        let evidence_ids: BTreeSet<&str> = self
            .evidence
            .iter()
            .map(|evidence| evidence.id.as_str())
            .collect();
        let passed_proof_ids: BTreeSet<&str> = self
            .proofs
            .iter()
            .filter(|proof| {
                proof.passed
                    && proof
                        .obligations
                        .iter()
                        .all(|obligation| obligation.satisfied)
            })
            .map(|proof| proof.id.as_str())
            .collect();
        let conflicted_claim_ids: BTreeSet<&str> = self
            .conflicts
            .iter()
            .filter(|conflict| !conflict.resolved)
            .flat_map(|conflict| conflict.claim_ids.iter().map(String::as_str))
            .collect();
        self.claims
            .iter()
            .filter(|claim| {
                claim.usability == Usability::Verified
                    && !claim.evidence_ids.is_empty()
                    && claim
                        .evidence_ids
                        .iter()
                        .all(|id| evidence_ids.contains(id.as_str()))
                    && claim
                        .proof_id
                        .as_deref()
                        .is_some_and(|id| passed_proof_ids.contains(id))
                    && !conflicted_claim_ids.contains(claim.id.as_str())
            })
            .map(|claim| claim.id.as_str())
            .collect()
    }

    /// All symbol IDs with independently proven addressability and signature
    /// claims.
    pub fn verified_callable_symbol_ids(&self) -> BTreeSet<&str> {
        let proven = self.proven_claim_ids();
        let mut callable = BTreeSet::new();
        let mut signatures = BTreeSet::new();
        for claim in self
            .claims
            .iter()
            .filter(|claim| proven.contains(claim.id.as_str()))
        {
            match &claim.subject {
                ClaimSubject::Callable { symbol_id, .. } => {
                    callable.insert(symbol_id.as_str());
                }
                ClaimSubject::Signature { symbol_id, .. } => {
                    signatures.insert(symbol_id.as_str());
                }
                _ => {}
            }
        }
        callable.intersection(&signatures).copied().collect()
    }

    /// A verified label is valid only when the claim is backed by recorded
    /// evidence, a passing proof, and no unresolved conflict.
    pub fn claim_is_proven(&self, claim: &Claim) -> bool {
        if claim.usability != Usability::Verified || claim.evidence_ids.is_empty() {
            return false;
        }
        let evidence_exists = claim
            .evidence_ids
            .iter()
            .all(|id| self.evidence.iter().any(|item| item.id == *id));
        let proof_passed = claim.proof_id.as_deref().is_some_and(|id| {
            self.proofs.iter().any(|proof| {
                proof.id == id
                    && proof.passed
                    && proof
                        .obligations
                        .iter()
                        .all(|obligation| obligation.satisfied)
            })
        });
        let conflicted = self.conflicts.iter().any(|conflict| {
            !conflict.resolved && conflict.claim_ids.iter().any(|id| id == &claim.id)
        });
        evidence_exists && proof_passed && !conflicted
    }

    /// Callable output requires independently proven addressability and ABI
    /// signature claims for the same symbol.
    pub fn symbol_is_verified_callable(&self, symbol_id: &str) -> bool {
        let callable = self.claims.iter().any(|claim| {
            matches!(&claim.subject, ClaimSubject::Callable { symbol_id: id, .. } if id == symbol_id)
                && self.claim_is_proven(claim)
        });
        let signature = self.claims.iter().any(|claim| {
            matches!(&claim.subject, ClaimSubject::Signature { symbol_id: id, .. } if id == symbol_id)
                && self.claim_is_proven(claim)
        });
        callable && signature
    }

    pub fn vtable_slot_is_verified(
        &self,
        owner: &str,
        table_rva: u32,
        table_object_offset: Option<i64>,
        slot: u32,
        target_rva: u32,
    ) -> bool {
        self.claims.iter().any(|claim| {
            matches!(
                claim.subject,
                ClaimSubject::VtableSlot {
                    table_rva: table,
                    table_object_offset: claim_offset,
                    slot: index,
                    target_rva: target,
                    owner: ref claim_owner,
                } if claim_owner == owner && table == table_rva && claim_offset == table_object_offset && index == slot && target == target_rva
            ) && self.claim_is_proven(claim)
        })
    }

    /// Upgrade a deserialized legacy database without fabricating proof records.
    /// Legacy facts remain available in their original flattened sections and
    /// are explicitly marked as unproven until re-analysis supplies evidence.
    pub fn migrate(mut self) -> Self {
        if self.schema < 2 {
            self.capabilities.push(Capability {
                id: "schema-v1-legacy-facts".into(),
                status: CapabilityStatus::Partial,
                analyzer: "schema-migration".into(),
                reason:
                    "legacy flattened facts retained; proof graph unavailable until re-analysis"
                        .into(),
            });
            self.schema = 2;
        }
        if self.schema < 3 {
            self.capabilities.push(Capability {
                id: "schema-v3-semantic-projection".into(),
                status: CapabilityStatus::Partial,
                analyzer: "schema-migration".into(),
                reason: "semantic projection is empty until refine --semantic is run".into(),
            });
            self.schema = 3;
        }
        self
    }
}

pub const SCHEMA_VERSION: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_claim() -> Claim {
        Claim {
            id: "claim:test".into(),
            subject: ClaimSubject::Text {
                category: "test".into(),
                text: "fact".into(),
            },
            status: ClaimStatus::Observed,
            usability: Usability::Verified,
            evidence_ids: vec!["ev:test".into()],
            proof_id: Some("proof:test".into()),
        }
    }

    #[test]
    fn verified_claim_requires_evidence_and_passing_proof() {
        let claim = verified_claim();
        let mut db = Database::default();
        assert!(!db.claim_is_proven(&claim));

        db.evidence.push(Evidence {
            id: "ev:test".into(),
            kind: EvidenceKind::Manual,
            tool: EvidenceTool::Human,
            rule_id: "test".into(),
            rule_version: 1,
            location: EvidenceLocation::default(),
            observation: EvidenceObservation::Text {
                text: "fact".into(),
            },
        });
        db.proofs.push(Proof {
            id: "proof:test".into(),
            rule_id: "test".into(),
            rule_version: 1,
            passed: true,
            obligations: vec![ProofObligation {
                name: "test".into(),
                satisfied: true,
                detail: "satisfied".into(),
            }],
        });
        assert!(db.claim_is_proven(&claim));

        db.conflicts.push(Conflict {
            id: "conflict:test".into(),
            claim_ids: vec![claim.id.clone()],
            reason: "contradiction".into(),
            resolved: false,
        });
        assert!(!db.claim_is_proven(&claim));
    }
}
