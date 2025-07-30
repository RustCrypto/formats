module Trait_instances

[@FStar.Tactics.Typeclasses.tcinstance]
val write_vec: Std.Io.t_Write (Alloc.Vec.t_Vec Rust_primitives.Integers.u8
            Alloc.Alloc.t_Global)