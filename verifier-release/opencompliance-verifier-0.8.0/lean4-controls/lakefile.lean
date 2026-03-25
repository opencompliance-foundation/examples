import Lake
open Lake DSL

package «opencompliance» where
  version := v!"0.1.0"
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

require «legal-lean» from git
  "https://github.com/edu-ap/legal-lean.git" @ "main"

@[default_target]
lean_lib «OpenCompliance» where
  roots := #[`OpenCompliance]
