import Lake
open Lake DSL

require mathlib from git
  "https://github.com/leanprover-community/mathlib4" @ "v4.16.0"

package phalanx where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib Phalanx where
  srcDir := "Phalanx"
  roots := #[`MoldCommutativity]
