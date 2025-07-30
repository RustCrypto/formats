module Zeroize
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

class t_Zeroize (v_Self: Type0) = {
  (* [@@@ FStar.Tactics.Typeclasses.no_method]_super_4726684624731801277:Core.Marker.t_MetaSized
  v_Self; *)
  f_zeroize_pre:v_Self -> Type0;
  f_zeroize_post:v_Self -> v_Self -> Type0;
  f_zeroize:x0: v_Self
    -> Prims.Pure v_Self
        (f_zeroize_pre x0)
        (fun result ->
            f_zeroize_post x0 result)
}