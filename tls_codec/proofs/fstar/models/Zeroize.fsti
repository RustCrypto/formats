module Zeroize
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

class t_Zeroize (v_Self: Type0) = {
  f_zeroize_pre:v_Self -> Type0;
  f_zeroize_post:v_Self -> v_Self -> Type0;
  f_zeroize:x0: v_Self
    -> Prims.Pure v_Self
        (f_zeroize_pre x0)
        (fun result ->
            f_zeroize_post x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl
      (#v_Z: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve
            ()]
          i0:
          t_Zeroize v_Z)
    : t_Zeroize
    (Alloc.Vec.t_Vec v_Z
        Alloc.Alloc.t_Global) =
  {
    f_zeroize_pre
    =
    (fun
        (self:
          Alloc.Vec.t_Vec v_Z
            Alloc.Alloc.t_Global)
        ->
        true);
    f_zeroize_post
    =
    (fun
        (self:
          Alloc.Vec.t_Vec v_Z
            Alloc.Alloc.t_Global)
        (out:
          Alloc.Vec.t_Vec v_Z
            Alloc.Alloc.t_Global)
        ->
        true);
    f_zeroize
    =
    fun
      (self:
        Alloc.Vec.t_Vec v_Z
          Alloc.Alloc.t_Global)
      ->
      self
  }

