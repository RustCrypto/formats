module Tls_codec.Quic_vec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Tls_codec in
  let open Tls_codec.Primitives in
  let open Tls_codec.Tls_vec in
  ()

let v_MAX_LEN: u64 = (mk_u64 1 <<! mk_i32 62 <: u64) -! mk_u64 1

let v_MAX_LEN_LEN_LOG: usize = mk_usize 3

let calculate_length (len_len_byte: u8) : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let (length: usize):usize =
    Core.Convert.f_into #u8 #usize #FStar.Tactics.Typeclasses.solve (len_len_byte &. mk_u8 63 <: u8)
  in
  let len_len_log:usize =
    Core.Convert.f_into #u8
      #usize
      #FStar.Tactics.Typeclasses.solve
      (len_len_byte >>! mk_i32 6 <: u8)
  in
  let _:Prims.unit =
    if ~.false
    then
      let _:Prims.unit =
        if true
        then
          let _:Prims.unit = Hax_lib.v_assert (len_len_log <=. v_MAX_LEN_LEN_LOG <: bool) in
          ()
      in
      ()
  in
  if len_len_log >. v_MAX_LEN_LEN_LOG
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    let len_len:usize =
      match len_len_log <: usize with
      | Rust_primitives.Integers.MkInt 0 -> mk_usize 1
      | Rust_primitives.Integers.MkInt 1 -> mk_usize 2
      | Rust_primitives.Integers.MkInt 2 -> mk_usize 4
      | Rust_primitives.Integers.MkInt 3 -> mk_usize 8
      | _ ->
        Rust_primitives.Hax.never_to_any (Core.Panicking.panic "internal error: entered unreachable code"

            <:
            Rust_primitives.Hax.t_Never)
    in
    Core.Result.Result_Ok (length, len_len <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let length_encoding_bytes (length: u64) : Core.Result.t_Result usize Tls_codec.t_Error =
  let _:Prims.unit =
    if ~.false
    then
      let _:Prims.unit =
        if true
        then
          let _:Prims.unit = Hax_lib.v_assert (length <=. v_MAX_LEN <: bool) in
          ()
      in
      ()
  in
  if length >. v_MAX_LEN
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result usize Tls_codec.t_Error
  else
    Core.Result.Result_Ok
    (if length <=. mk_u64 63
      then mk_usize 1
      else
        if length <=. mk_u64 16383
        then mk_usize 2
        else if length <=. mk_u64 1073741823 then mk_usize 4 else mk_usize 8)
    <:
    Core.Result.t_Result usize Tls_codec.t_Error

let check_min_length (length len_len: usize) : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  if false
  then
    match
      length_encoding_bytes (cast (length <: usize) <: u64)
      <:
      Core.Result.t_Result usize Tls_codec.t_Error
    with
    | Core.Result.Result_Ok min_len_len ->
      if min_len_len <>. len_len
      then
        Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
        <:
        Core.Result.t_Result Prims.unit Tls_codec.t_Error
      else
        Core.Result.Result_Ok (() <: Prims.unit)
        <:
        Core.Result.t_Result Prims.unit Tls_codec.t_Error
    | Core.Result.Result_Err err ->
      Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

let read_variable_length_bytes (bytes: t_Slice u8)
    : Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error =
  match
    Tls_codec.f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u8 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len_len_byte, remainder) ->
    (match
        calculate_length len_len_byte <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok (length, len_len) ->
        (match
            Rust_primitives.Hax.Folds.fold_range_return (mk_usize 1)
              len_len
              (fun temp_0_ temp_1_ ->
                  let length, remainder:(usize & t_Slice u8) = temp_0_ in
                  let _:usize = temp_1_ in
                  true)
              (length, remainder <: (usize & t_Slice u8))
              (fun temp_0_ temp_1_ ->
                  let length, remainder:(usize & t_Slice u8) = temp_0_ in
                  let _:usize = temp_1_ in
                  match
                    Tls_codec.f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve remainder
                    <:
                    Core.Result.t_Result (u8 & t_Slice u8) Tls_codec.t_Error
                  with
                  | Core.Result.Result_Ok (next, next_remainder) ->
                    let remainder:t_Slice u8 = next_remainder in
                    let length:usize =
                      (length <<! mk_i32 8 <: usize) +!
                      (Core.Convert.f_from #usize #u8 #FStar.Tactics.Typeclasses.solve next <: usize
                      )
                    in
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (length, remainder <: (usize & t_Slice u8))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
                          (Prims.unit & (usize & t_Slice u8))) (usize & t_Slice u8)
                  | Core.Result.Result_Err err ->
                    Core.Ops.Control_flow.ControlFlow_Break
                    (Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Result.Result_Err err
                        <:
                        Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
                        (Prims.unit & (usize & t_Slice u8)))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
                          (Prims.unit & (usize & t_Slice u8))) (usize & t_Slice u8))
            <:
            Core.Ops.Control_flow.t_ControlFlow
              (Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
              (usize & t_Slice u8)
          with
          | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
          | Core.Ops.Control_flow.ControlFlow_Continue (length, remainder) ->
            match
              check_min_length length len_len <: Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              Core.Result.Result_Ok
              ((length, len_len <: (usize & usize)), remainder <: ((usize & usize) & t_Slice u8))
              <:
              Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error
            | Core.Result.Result_Err err ->
              Core.Result.Result_Err err
              <:
              Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error

let write_variable_length (content_length: usize)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error =
  match
    Core.Convert.f_try_into #usize #u64 #FStar.Tactics.Typeclasses.solve content_length
    <:
    Core.Result.t_Result u64 Core.Num.Error.t_TryFromIntError
  with
  | Core.Result.Result_Ok hoist71 ->
    (match length_encoding_bytes hoist71 <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok len_len ->
        let _:Prims.unit =
          if ~.false
          then
            let _:Prims.unit =
              if true
              then
                let _:Prims.unit =
                  if ~.(len_len <=. mk_usize 8 <: bool)
                  then
                    Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1
                              (mk_usize 1)
                              (mk_usize 1)
                              (let list = ["Invalid vector len_len "] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                                Rust_primitives.Hax.array_of_list 1 list)
                              (let list =
                                  [
                                    Core.Fmt.Rt.impl__new_display #usize len_len
                                    <:
                                    Core.Fmt.Rt.t_Argument
                                  ]
                                in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                                Rust_primitives.Hax.array_of_list 1 list)
                            <:
                            Core.Fmt.t_Arguments)
                        <:
                        Rust_primitives.Hax.t_Never)
                in
                ()
            in
            ()
        in
        if len_len >. mk_usize 8
        then
          Core.Result.Result_Err (Tls_codec.Error_LibraryError <: Tls_codec.t_Error)
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
        else
          let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Alloc.Vec.from_elem #u8 (mk_u8 0) len_len
          in
          (match len_len <: usize with
            | Rust_primitives.Integers.MkInt 1 ->
              let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                  (mk_usize 0)
                  (mk_u8 0)
              in
              let len:usize = content_length in
              let l:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_bytes in
              let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  l
                  (fun temp_0_ temp_1_ ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                  (fun temp_0_ i ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let i:usize = i in
                      let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                          ((l -! i <: usize) -! mk_usize 1 <: usize)
                          ((length_bytes.[ (l -! i <: usize) -! mk_usize 1 <: usize ] <: u8) |.
                            (cast (len &. mk_usize 255 <: usize) <: u8)
                            <:
                            u8)
                      in
                      let len:usize = len >>! mk_i32 8 in
                      len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              in
              Core.Result.Result_Ok length_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
            | Rust_primitives.Integers.MkInt 2 ->
              let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                  (mk_usize 0)
                  (mk_u8 64)
              in
              let len:usize = content_length in
              let l:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_bytes in
              let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  l
                  (fun temp_0_ temp_1_ ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                  (fun temp_0_ i ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let i:usize = i in
                      let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                          ((l -! i <: usize) -! mk_usize 1 <: usize)
                          ((length_bytes.[ (l -! i <: usize) -! mk_usize 1 <: usize ] <: u8) |.
                            (cast (len &. mk_usize 255 <: usize) <: u8)
                            <:
                            u8)
                      in
                      let len:usize = len >>! mk_i32 8 in
                      len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              in
              Core.Result.Result_Ok length_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
            | Rust_primitives.Integers.MkInt 4 ->
              let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                  (mk_usize 0)
                  (mk_u8 128)
              in
              let len:usize = content_length in
              let l:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_bytes in
              let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  l
                  (fun temp_0_ temp_1_ ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                  (fun temp_0_ i ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let i:usize = i in
                      let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                          ((l -! i <: usize) -! mk_usize 1 <: usize)
                          ((length_bytes.[ (l -! i <: usize) -! mk_usize 1 <: usize ] <: u8) |.
                            (cast (len &. mk_usize 255 <: usize) <: u8)
                            <:
                            u8)
                      in
                      let len:usize = len >>! mk_i32 8 in
                      len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              in
              Core.Result.Result_Ok length_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
            | Rust_primitives.Integers.MkInt 8 ->
              let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                  (mk_usize 0)
                  (mk_u8 192)
              in
              let len:usize = content_length in
              let l:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_bytes in
              let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
                  l
                  (fun temp_0_ temp_1_ ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let _:usize = temp_1_ in
                      true)
                  (len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                  (fun temp_0_ i ->
                      let len, length_bytes:(usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                        temp_0_
                      in
                      let i:usize = i in
                      let length_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
                        Rust_primitives.Hax.Monomorphized_update_at.update_at_usize length_bytes
                          ((l -! i <: usize) -! mk_usize 1 <: usize)
                          ((length_bytes.[ (l -! i <: usize) -! mk_usize 1 <: usize ] <: u8) |.
                            (cast (len &. mk_usize 255 <: usize) <: u8)
                            <:
                            u8)
                      in
                      let len:usize = len >>! mk_i32 8 in
                      len, length_bytes <: (usize & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
              in
              Core.Result.Result_Ok length_bytes
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
            | _ ->
              let _:Prims.unit =
                if ~.false
                then
                  let _:Prims.unit =
                    if true
                    then
                      let _:Prims.unit =
                        if ~.false
                        then
                          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1
                                    (mk_usize 1)
                                    (mk_usize 1)
                                    (let list = ["Invalid vector len_len "] in
                                      FStar.Pervasives.assert_norm
                                      (Prims.eq2 (List.Tot.length list) 1);
                                      Rust_primitives.Hax.array_of_list 1 list)
                                    (let list =
                                        [
                                          Core.Fmt.Rt.impl__new_display #usize len_len
                                          <:
                                          Core.Fmt.Rt.t_Argument
                                        ]
                                      in
                                      FStar.Pervasives.assert_norm
                                      (Prims.eq2 (List.Tot.length list) 1);
                                      Rust_primitives.Hax.array_of_list 1 list)
                                  <:
                                  Core.Fmt.t_Arguments)
                              <:
                              Rust_primitives.Hax.t_Never)
                      in
                      ()
                  in
                  ()
              in
              Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err
    (Core.Convert.f_from #Tls_codec.t_Error
        #Core.Num.Error.t_TryFromIntError
        #FStar.Tactics.Typeclasses.solve
        err)
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_Slice v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_Slice v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_Slice v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_Slice v_T) ->
      let content_length:usize =
        Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
          #FStar.Tactics.Typeclasses.solve
          #usize
          (Core.Slice.impl__iter #v_T self <: Core.Slice.Iter.t_Iter v_T)
          (mk_usize 0)
          (fun acc e ->
              let acc:usize = acc in
              let e:v_T = e in
              acc +!
              (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
              <:
              usize)
      in
      let len_len:usize =
        Core.Result.impl__unwrap_or #usize
          #Tls_codec.t_Error
          (length_encoding_bytes (cast (content_length <: usize) <: u64)
            <:
            Core.Result.t_Result usize Tls_codec.t_Error)
          (mk_usize 0)
      in
      content_length +! len_len
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_tls_serialized_len_pre = (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialized_len_post
    =
    (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) ->
      Tls_codec.f_tls_serialized_len #(t_Slice v_T)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Vec.impl_1__as_slice #v_T #Alloc.Alloc.t_Global self <: t_Slice v_T)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_tls_serialized_len_pre = (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialized_len_post
    =
    (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) ->
      Tls_codec.f_tls_serialized_len #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out:
          Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
            Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        read_variable_length_bytes bytes
        <:
        Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok ((length, len_len), remainder) ->
        if length =. mk_usize 0
        then
          Core.Result.Result_Ok
          (Alloc.Vec.impl__new #v_T (), remainder
            <:
            (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8))
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
            Tls_codec.t_Error
        else
          let result:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global = Alloc.Vec.impl__new #v_T () in
          let read:usize = len_len in
          (match
              Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
                    let read, remainder, result:(usize & t_Slice u8 &
                      Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    (read -! len_len <: usize) <. length <: bool)
                (fun temp_0_ ->
                    let read, remainder, result:(usize & t_Slice u8 &
                      Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    true)
                (fun temp_0_ ->
                    let read, remainder, result:(usize & t_Slice u8 &
                      Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
                (read, remainder, result
                  <:
                  (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
                (fun temp_0_ ->
                    let read, remainder, result:(usize & t_Slice u8 &
                      Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
                      temp_0_
                    in
                    match
                      Tls_codec.f_tls_deserialize_bytes #v_T
                        #FStar.Tactics.Typeclasses.solve
                        remainder
                      <:
                      Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
                    with
                    | Core.Result.Result_Ok (element, next_remainder) ->
                      let remainder:t_Slice u8 = next_remainder in
                      let read:usize =
                        read +!
                        (Tls_codec.f_tls_serialized_len #v_T
                            #FStar.Tactics.Typeclasses.solve
                            element
                          <:
                          usize)
                      in
                      let result:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
                        Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global result element
                      in
                      Core.Ops.Control_flow.ControlFlow_Continue
                      (read, remainder, result
                        <:
                        (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (Core.Result.t_Result
                                (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                                Tls_codec.t_Error)
                            (Prims.unit &
                              (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                        (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    | Core.Result.Result_Err err ->
                      Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Ops.Control_flow.ControlFlow_Break
                        (Core.Result.Result_Err err
                          <:
                          Core.Result.t_Result
                            (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                            Tls_codec.t_Error)
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (Core.Result.t_Result
                              (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                              Tls_codec.t_Error)
                          (Prims.unit &
                            (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (Core.Result.t_Result
                                (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                                Tls_codec.t_Error)
                            (Prims.unit &
                              (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                        (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
              <:
              Core.Ops.Control_flow.t_ControlFlow
                (Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                    Tls_codec.t_Error)
                (usize & t_Slice u8 & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            with
            | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
            | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
              Core.Result.Result_Ok
              (result, remainder <: (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8))
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
                Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & t_Slice u8)
          Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_SerializeBytes v_T)
    : Tls_codec.t_SerializeBytes (t_Slice v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_Slice v_T) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_Slice v_T)
        (out1: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_Slice v_T) ->
      let content_length:usize =
        Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
          #FStar.Tactics.Typeclasses.solve
          #usize
          (Core.Slice.impl__iter #v_T self <: Core.Slice.Iter.t_Iter v_T)
          (mk_usize 0)
          (fun acc e ->
              let acc:usize = acc in
              let e:v_T = e in
              acc +!
              (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
              <:
              usize)
      in
      match
        write_variable_length content_length
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok length ->
        let len_len:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length in
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl__with_capacity #u8 (content_length +! len_len <: usize)
        in
        let tmp0, tmp1:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
          Alloc.Vec.impl_1__append #u8 #Alloc.Alloc.t_Global out length
        in
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tmp0 in
        let length:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tmp1 in
        let _:Prims.unit = () in
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T self <: Core.Slice.Iter.t_Iter v_T)
                <:
                Core.Slice.Iter.t_Iter v_T)
              out
              (fun out e ->
                  let out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
                    out
                  in
                  let e:v_T = e in
                  match
                    Tls_codec.f_tls_serialize_bytes #v_T #FStar.Tactics.Typeclasses.solve e
                    <:
                    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
                  with
                  | Core.Result.Result_Ok hoist76 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (Alloc.Vec.impl_1__append #u8 #Alloc.Alloc.t_Global out hoist76
                      <:
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                              Tls_codec.t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  | Core.Result.Result_Err err ->
                    Core.Ops.Control_flow.ControlFlow_Break
                    (Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Result.Result_Err err
                        <:
                        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                          Tls_codec.t_Error)
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                            Tls_codec.t_Error)
                        (Prims.unit &
                          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                              Tls_codec.t_Error)
                          (Prims.unit &
                            (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)))
                      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
                        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            <:
            Core.Ops.Control_flow.t_ControlFlow
              (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
              (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          with
          | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
          | Core.Ops.Control_flow.ControlFlow_Continue out ->
            if
              ((Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global out <: usize) -! len_len <: usize) <>.
              content_length
            then
              Core.Result.Result_Err (Tls_codec.Error_LibraryError <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
            else
              Core.Result.Result_Ok out
              <:
              Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_SerializeBytes v_T)
    : Tls_codec.t_SerializeBytes (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) ->
      Tls_codec.f_tls_serialize_bytes #(t_Slice v_T)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Vec.impl_1__as_slice #v_T #Alloc.Alloc.t_Global self <: t_Slice v_T)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_SerializeBytes v_T)
    : Tls_codec.t_SerializeBytes (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) ->
      Tls_codec.f_tls_serialize_bytes #(t_Slice v_T)
        #FStar.Tactics.Typeclasses.solve
        (Alloc.Vec.impl_1__as_slice #v_T #Alloc.Alloc.t_Global self <: t_Slice v_T)
  }

let write_hex (f: Core.Fmt.t_Formatter) (data: t_Slice u8)
    : (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
  if ~.(Core.Slice.impl__is_empty #u8 data <: bool)
  then
    let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
      Core.Fmt.impl_11__write_fmt f
        (Core.Fmt.Rt.impl_2__new_const (mk_usize 1)
            (let list = ["0x"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core.Fmt.t_Arguments)
    in
    let f:Core.Fmt.t_Formatter = tmp0 in
    match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
    | Core.Result.Result_Ok _ ->
      (match
          Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(t_Slice u8)
                #FStar.Tactics.Typeclasses.solve
                data
              <:
              Core.Slice.Iter.t_Iter u8)
            f
            (fun f byte ->
                let f:Core.Fmt.t_Formatter = f in
                let byte:u8 = byte in
                let tmp0, out:(Core.Fmt.t_Formatter &
                  Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
                  Core.Fmt.impl_11__write_fmt f
                    (Core.Fmt.Rt.impl_2__new_v1_formatted ((let list = [""] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          <:
                          t_Slice string)
                        ((let list = [Core.Fmt.Rt.impl__new_lower_hex #u8 byte] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          <:
                          t_Slice Core.Fmt.Rt.t_Argument)
                        ((let list =
                              [
                                {
                                  Core.Fmt.Rt.f_position = mk_usize 0;
                                  Core.Fmt.Rt.f_flags = mk_u32 3909091360;
                                  Core.Fmt.Rt.f_precision
                                  =
                                  Core.Fmt.Rt.Count_Implied <: Core.Fmt.Rt.t_Count;
                                  Core.Fmt.Rt.f_width
                                  =
                                  Core.Fmt.Rt.Count_Is (mk_u16 2) <: Core.Fmt.Rt.t_Count
                                }
                                <:
                                Core.Fmt.Rt.t_Placeholder
                              ]
                            in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                          <:
                          t_Slice Core.Fmt.Rt.t_Placeholder)
                        (Core.Fmt.Rt.impl_UnsafeArg__new () <: Core.Fmt.Rt.t_UnsafeArg)
                      <:
                      Core.Fmt.t_Arguments)
                in
                let f:Core.Fmt.t_Formatter = tmp0 in
                match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
                | Core.Result.Result_Ok ok ->
                  Core.Ops.Control_flow.ControlFlow_Continue f
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
                        (Prims.unit & Core.Fmt.t_Formatter)) Core.Fmt.t_Formatter
                | Core.Result.Result_Err err ->
                  Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Ops.Control_flow.ControlFlow_Break
                    (f,
                      (Core.Result.Result_Err err
                        <:
                        Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
                      <:
                      (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
                      (Prims.unit & Core.Fmt.t_Formatter))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Ops.Control_flow.t_ControlFlow
                        (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
                        (Prims.unit & Core.Fmt.t_Formatter)) Core.Fmt.t_Formatter)
          <:
          Core.Ops.Control_flow.t_ControlFlow
            (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            Core.Fmt.t_Formatter
        with
        | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
        | Core.Ops.Control_flow.ControlFlow_Continue f ->
          let hax_temp_output:Core.Result.t_Result Prims.unit Core.Fmt.t_Error =
            Core.Result.Result_Ok (() <: Prims.unit)
            <:
            Core.Result.t_Result Prims.unit Core.Fmt.t_Error
          in
          f, hax_temp_output
          <:
          (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
    | Core.Result.Result_Err err ->
      f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
      <:
      (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
  else
    let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
      Core.Fmt.impl_11__write_fmt f
        (Core.Fmt.Rt.impl_2__new_const (mk_usize 1)
            (let list = ["b\"\""] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core.Fmt.t_Arguments)
    in
    let f:Core.Fmt.t_Formatter = tmp0 in
    match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
    | Core.Result.Result_Ok _ ->
      let hax_temp_output:Core.Result.t_Result Prims.unit Core.Fmt.t_Error =
        Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error
      in
      f, hax_temp_output
      <:
      (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
    | Core.Result.Result_Err err ->
      f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
      <:
      (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)

/// Variable-length encoded byte vectors.
/// Use this struct if bytes are encoded.
/// This is faster than the generic version.
type t_VLBytes = { f_vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl_16: Core.Clone.t_Clone t_VLBytes = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Core.Marker.t_StructuralPartialEq t_VLBytes

unfold
let impl_17 = impl_17'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core.Cmp.t_PartialEq t_VLBytes t_VLBytes

unfold
let impl_18 = impl_18'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Core.Cmp.t_Eq t_VLBytes

unfold
let impl_19 = impl_19'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Core.Hash.t_Hash t_VLBytes

unfold
let impl_20 = impl_20'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Core.Cmp.t_PartialOrd t_VLBytes t_VLBytes

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Core.Cmp.t_Ord t_VLBytes

unfold
let impl_21 = impl_21'

/// Generate a new variable-length byte vector.
let impl_VLBytes__new (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_VLBytes =
  { f_vec = vec } <: t_VLBytes

let impl_VLBytes__vec (self: t_VLBytes) : t_Slice u8 =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_23: Core.Fmt.t_Debug t_VLBytes =
  {
    f_fmt_pre = (fun (self: t_VLBytes) (f: Core.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_VLBytes)
        (f: Core.Fmt.t_Formatter)
        (out1: (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_VLBytes) (f: Core.Fmt.t_Formatter) ->
      let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
        Core.Fmt.impl_11__write_fmt f
          (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 1)
              (mk_usize 0)
              (let list = ["VLBytes { "] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              (Core.Fmt.Rt.impl__none () <: t_Array Core.Fmt.Rt.t_Argument (mk_usize 0))
            <:
            Core.Fmt.t_Arguments)
      in
      let f:Core.Fmt.t_Formatter = tmp0 in
      match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
      | Core.Result.Result_Ok _ ->
        let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
          write_hex f (impl_VLBytes__vec self <: t_Slice u8)
        in
        let f:Core.Fmt.t_Formatter = tmp0 in
        (match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
          | Core.Result.Result_Ok _ ->
            let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            =
              Core.Fmt.impl_11__write_fmt f
                (Core.Fmt.Rt.impl_2__new_const (mk_usize 1)
                    (let list = [" }"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core.Fmt.t_Arguments)
            in
            let f:Core.Fmt.t_Formatter = tmp0 in
            let hax_temp_output:Core.Result.t_Result Prims.unit Core.Fmt.t_Error = out in
            f, hax_temp_output
            <:
            (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
          | Core.Result.Result_Err err ->
            f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            <:
            (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
      | Core.Result.Result_Err err ->
        f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
        <:
        (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
  }

/// Get a reference to the vlbytes's vec.
let impl_VLBytes__as_slice (self: t_VLBytes) : t_Slice u8 =
  Core.Convert.f_as_ref #(t_Slice u8)
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (impl_VLBytes__vec self <: t_Slice u8)

/// Add an element to this.
/// Remove the last element.
let impl_VLBytes__pop (self: t_VLBytes) : (t_VLBytes & Core.Option.t_Option u8) =
  let hax_temp_output:Core.Option.t_Option u8 =
    Core.Option.Option_None <: Core.Option.t_Option u8
  in
  self, hax_temp_output <: (t_VLBytes & Core.Option.t_Option u8)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_25: Core.Convert.t_From t_VLBytes (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_VLBytes) -> true);
    f_from = fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_VLBytes__new vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_26: Core.Convert.t_From t_VLBytes (t_Slice u8) =
  {
    f_from_pre = (fun (slice: t_Slice u8) -> true);
    f_from_post = (fun (slice: t_Slice u8) (out: t_VLBytes) -> true);
    f_from
    =
    fun (slice: t_Slice u8) ->
      impl_VLBytes__new (Alloc.Slice.impl__to_vec #u8 slice
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_27 (v_N: usize) : Core.Convert.t_From t_VLBytes (t_Array u8 v_N) =
  {
    f_from_pre = (fun (slice: t_Array u8 v_N) -> true);
    f_from_post = (fun (slice: t_Array u8 v_N) (out: t_VLBytes) -> true);
    f_from
    =
    fun (slice: t_Array u8 v_N) ->
      impl_VLBytes__new (Alloc.Slice.impl__to_vec #u8 (slice <: t_Slice u8)
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_28: Core.Convert.t_AsRef t_VLBytes (t_Slice u8) =
  {
    f_as_ref_pre = (fun (self: t_VLBytes) -> true);
    f_as_ref_post = (fun (self: t_VLBytes) (out: t_Slice u8) -> true);
    f_as_ref = fun (self: t_VLBytes) -> impl_VLBytes__vec self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_8: Core.Convert.t_From (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_VLBytes =
  {
    f_from_pre = (fun (b: t_VLBytes) -> true);
    f_from_post = (fun (b: t_VLBytes) (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from = fun (b: t_VLBytes) -> b.f_vec
  }

let tls_serialize_bytes_len (bytes: t_Slice u8) : usize =
  let content_length:usize = Core.Slice.impl__len #u8 bytes in
  let len_len:usize =
    Core.Result.impl__unwrap_or #usize
      #Tls_codec.t_Error
      (length_encoding_bytes (cast (content_length <: usize) <: u64)
        <:
        Core.Result.t_Result usize Tls_codec.t_Error)
      (mk_usize 0)
  in
  content_length +! len_len

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_9: Tls_codec.t_Size t_VLBytes =
  {
    f_tls_serialized_len_pre = (fun (self: t_VLBytes) -> true);
    f_tls_serialized_len_post = (fun (self: t_VLBytes) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_VLBytes) -> tls_serialize_bytes_len (impl_VLBytes__as_slice self <: t_Slice u8)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_10: Tls_codec.t_DeserializeBytes t_VLBytes =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        read_variable_length_bytes bytes
        <:
        Core.Result.t_Result ((usize & usize) & t_Slice u8) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok ((length, _), remainder) ->
        if length =. mk_usize 0
        then
          Core.Result.Result_Ok
          (impl_VLBytes__new (Alloc.Vec.impl__new #u8 () <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global),
            remainder
            <:
            (t_VLBytes & t_Slice u8))
          <:
          Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error
        else
          let _:Prims.unit =
            if ~.false
            then
              let _:Prims.unit =
                if true
                then
                  let _:Prims.unit =
                    if ~.(length <=. (cast (v_MAX_LEN <: u64) <: usize) <: bool)
                    then
                      Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1
                                (mk_usize 3)
                                (mk_usize 2)
                                (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                                  Rust_primitives.Hax.array_of_list 3 list)
                                (let list =
                                    [
                                      Core.Fmt.Rt.impl__new_display #usize length
                                      <:
                                      Core.Fmt.Rt.t_Argument;
                                      Core.Fmt.Rt.impl__new_display #u64 v_MAX_LEN
                                      <:
                                      Core.Fmt.Rt.t_Argument
                                    ]
                                  in
                                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                                  Rust_primitives.Hax.array_of_list 2 list)
                              <:
                              Core.Fmt.t_Arguments)
                          <:
                          Rust_primitives.Hax.t_Never)
                  in
                  ()
              in
              ()
          in
          if length >. (cast (v_MAX_LEN <: u64) <: usize)
          then
            Core.Result.Result_Err
            (Tls_codec.Error_DecodingError
              (Core.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                          (mk_usize 2)
                          (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                            Rust_primitives.Hax.array_of_list 3 list)
                          (let list =
                              [
                                Core.Fmt.Rt.impl__new_display #usize length
                                <:
                                Core.Fmt.Rt.t_Argument;
                                Core.Fmt.Rt.impl__new_display #u64 v_MAX_LEN
                                <:
                                Core.Fmt.Rt.t_Argument
                              ]
                            in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                        <:
                        Core.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String))
              <:
              Tls_codec.t_Error)
            <:
            Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error
          else
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #Tls_codec.t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeTo usize)
                      remainder
                      ({ Core.Ops.Range.f_end = length } <: Core.Ops.Range.t_RangeTo usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok vec ->
                Core.Result.Result_Ok
                (({ f_vec = Alloc.Slice.impl__to_vec #u8 vec } <: t_VLBytes),
                  remainder.[ { Core.Ops.Range.f_start = length }
                    <:
                    Core.Ops.Range.t_RangeFrom usize ]
                  <:
                  (t_VLBytes & t_Slice u8))
                <:
                Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error
              | Core.Result.Result_Err e_e ->
                let remaining_len:usize = Core.Slice.impl__len #u8 remainder in
                let _:Prims.unit =
                  if ~.false
                  then
                    let _:Prims.unit =
                      if true
                      then
                        let _:Prims.unit =
                          match remaining_len, length <: (usize & usize) with
                          | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
                        in
                        ()
                    in
                    ()
                in
                Core.Result.Result_Err
                (Tls_codec.Error_DecodingError
                  (Core.Hint.must_use #Alloc.String.t_String
                      (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                              (mk_usize 2)
                              (let list = [""; " bytes were read but "; " were expected"] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                                Rust_primitives.Hax.array_of_list 3 list)
                              (let list =
                                  [
                                    Core.Fmt.Rt.impl__new_display #usize remaining_len
                                    <:
                                    Core.Fmt.Rt.t_Argument;
                                    Core.Fmt.Rt.impl__new_display #usize length
                                    <:
                                    Core.Fmt.Rt.t_Argument
                                  ]
                                in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                                Rust_primitives.Hax.array_of_list 2 list)
                            <:
                            Core.Fmt.t_Arguments)
                        <:
                        Alloc.String.t_String))
                  <:
                  Tls_codec.t_Error)
                <:
                Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (t_VLBytes & t_Slice u8) Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_11: Tls_codec.t_Size t_VLBytes =
  {
    f_tls_serialized_len_pre = (fun (self: t_VLBytes) -> true);
    f_tls_serialized_len_post = (fun (self: t_VLBytes) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_VLBytes) ->
      Tls_codec.f_tls_serialized_len #t_VLBytes #FStar.Tactics.Typeclasses.solve self
  }

type t_VLByteSlice = | VLByteSlice : t_Slice u8 -> t_VLByteSlice

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_12: Core.Fmt.t_Debug t_VLByteSlice =
  {
    f_fmt_pre = (fun (self: t_VLByteSlice) (f: Core.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_VLByteSlice)
        (f: Core.Fmt.t_Formatter)
        (out1: (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_VLByteSlice) (f: Core.Fmt.t_Formatter) ->
      let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
        Core.Fmt.impl_11__write_fmt f
          (Core.Fmt.Rt.impl_2__new_const (mk_usize 1)
              (let list = ["VLByteSlice { "] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
            <:
            Core.Fmt.t_Arguments)
      in
      let f:Core.Fmt.t_Formatter = tmp0 in
      match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
      | Core.Result.Result_Ok _ ->
        let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
          write_hex f self._0
        in
        let f:Core.Fmt.t_Formatter = tmp0 in
        (match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
          | Core.Result.Result_Ok _ ->
            let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            =
              Core.Fmt.impl_11__write_fmt f
                (Core.Fmt.Rt.impl_2__new_const (mk_usize 1)
                    (let list = [" }"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core.Fmt.t_Arguments)
            in
            let f:Core.Fmt.t_Formatter = tmp0 in
            let hax_temp_output:Core.Result.t_Result Prims.unit Core.Fmt.t_Error = out in
            f, hax_temp_output
            <:
            (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
          | Core.Result.Result_Err err ->
            f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            <:
            (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
      | Core.Result.Result_Err err ->
        f, (Core.Result.Result_Err err <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
        <:
        (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
  }

/// Get the raw slice.
let impl_13__as_slice (self: t_VLByteSlice) : t_Slice u8 = self._0

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_14: Tls_codec.t_Size t_VLByteSlice =
  {
    f_tls_serialized_len_pre = (fun (self: t_VLByteSlice) -> true);
    f_tls_serialized_len_post = (fun (self: t_VLByteSlice) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_VLByteSlice) -> tls_serialize_bytes_len self._0
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_15: Tls_codec.t_Size t_VLByteSlice =
  {
    f_tls_serialized_len_pre = (fun (self: t_VLByteSlice) -> true);
    f_tls_serialized_len_post = (fun (self: t_VLByteSlice) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_VLByteSlice) -> tls_serialize_bytes_len self._0
  }
