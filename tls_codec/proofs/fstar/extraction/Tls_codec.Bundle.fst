module Tls_codec.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Std.Io in
  let open Std.Io.Error in
  ()

/// Errors that are thrown by this crate.
type t_Error =
  | Error_EncodingError : Alloc.String.t_String -> t_Error
  | Error_InvalidVectorLength : t_Error
  | Error_InvalidWriteLength : Alloc.String.t_String -> t_Error
  | Error_InvalidInput : t_Error
  | Error_DecodingError : Alloc.String.t_String -> t_Error
  | Error_EndOfStream : t_Error
  | Error_TrailingData : t_Error
  | Error_UnknownValue : u64 -> t_Error
  | Error_LibraryError : t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Core.Fmt.t_Debug t_Error

unfold
let impl_9 = impl_9'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Core.Marker.t_StructuralPartialEq t_Error

unfold
let impl_11 = impl_11'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Core.Cmp.t_PartialEq t_Error t_Error

unfold
let impl_12 = impl_12'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core.Cmp.t_Eq t_Error

unfold
let impl_10 = impl_10'

let impl_13: Core.Clone.t_Clone t_Error = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Core.Fmt.t_Display t_Error =
  {
    f_fmt_pre = (fun (self: t_Error) (f: Core.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_Error)
        (f: Core.Fmt.t_Formatter)
        (out1: (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_Error) (f: Core.Fmt.t_Formatter) ->
      let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
        Core.Fmt.impl_11__write_fmt f
          (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 1)
              (mk_usize 1)
              (let list = [""] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              (let list = [Core.Fmt.Rt.impl__new_debug #t_Error self <: Core.Fmt.Rt.t_Argument] in
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
  }
(* 
[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core.Error.t_Error t_Error =
  {
    _super_13156757144345117315 = FStar.Tactics.Typeclasses.solve;
    _super_389846626086906045 = FStar.Tactics.Typeclasses.solve
  } *)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Core.Convert.t_From t_Error Std.Io.Error.t_Error =
  {
    f_from_pre = (fun (e: Std.Io.Error.t_Error) -> true);
    f_from_post = (fun (e: Std.Io.Error.t_Error) (out: t_Error) -> true);
    f_from
    =
    fun (e: Std.Io.Error.t_Error) ->
      
        Error_DecodingError
        (Core.Hint.must_use #Alloc.String.t_String
            (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 1)
                    (mk_usize 1)
                    (let list = ["io error: "] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_debug #Std.Io.Error.t_Error e
                          <:
                          Core.Fmt.Rt.t_Argument
                        ]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core.Fmt.t_Arguments)
              <:
              Alloc.String.t_String))
        <:
        t_Error
  }

/// The `Size` trait needs to be implemented by any struct that should be
/// efficiently serialized.
/// This allows to collect the length of a serialized structure before allocating
/// memory.
class t_Size (v_Self: Type0) = {
  f_tls_serialized_len_pre:v_Self -> Type0;
  f_tls_serialized_len_post:v_Self -> usize -> Type0;
  f_tls_serialized_len:x0: v_Self
    -> Prims.Pure usize
        (f_tls_serialized_len_pre x0)
        (fun result -> f_tls_serialized_len_post x0 result)
}

/// The `Serialize` trait provides functions to serialize a struct or enum.
/// The trait provides two functions:
/// * `tls_serialize` that takes a buffer to write the serialization to
/// * `tls_serialize_detached` that returns a byte vector
class t_Serialize (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_2997919293107846837:t_Size v_Self;
  f_tls_serialize_pre:#v_W: Type0 -> {| i1: Std.Io.t_Write v_W |} -> v_Self -> v_W -> Type0;
  f_tls_serialize_post:
      #v_W: Type0 ->
      {| i1: Std.Io.t_Write v_W |} ->
      v_Self ->
      v_W ->
      (v_W & Core.Result.t_Result usize t_Error)
    -> Type0;
  f_tls_serialize:#v_W: Type0 -> {| i1: Std.Io.t_Write v_W |} -> x0: v_Self -> x1: v_W
    -> Prims.Pure (v_W & Core.Result.t_Result usize t_Error)
        (f_tls_serialize_pre #v_W #i1 x0 x1)
        (fun result -> f_tls_serialize_post #v_W #i1 x0 x1 result)
}

class t_SerializeDetached (v_Self: Type0) = {
  f_tls_serialize_detached_pre:v_Self -> Type0;
  f_tls_serialize_detached_post:
      v_Self ->
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
    -> Type0;
  f_tls_serialize_detached:x0: v_Self
    -> Prims.Pure (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        (f_tls_serialize_detached_pre x0)
        (fun result -> f_tls_serialize_detached_post x0 result)
}


[@@ FStar.Tactics.Typeclasses.tcinstance]
assume val impl_write_vec: Std.Io.t_Write (Alloc.Vec.t_Vec Rust_primitives.Integers.u8
            Alloc.Alloc.t_Global)
[@@ FStar.Tactics.Typeclasses.tcinstance]
assume val impl_read_vec: Std.Io.t_Read (Rust_primitives.Arrays.t_Slice Rust_primitives.Integers.u8
        )

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Serialize v_T)
    : t_SerializeDetached v_T =
  {
    f_tls_serialize_detached_pre = (fun (self: v_T) -> true);
    f_tls_serialize_detached_post
    =
    (fun
        (self: v_T)
        (out1: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_detached
    =
    fun (self: v_T) ->
      let buffer:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Alloc.Vec.impl__with_capacity #u8
          (f_tls_serialized_len #v_T #i1._super_2997919293107846837 self <: usize)
      in
      let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #v_T
          #FStar.Tactics.Typeclasses.solve
          #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          self
          buffer
      in
      let buffer:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tmp0 in
      match out <: Core.Result.t_Result usize t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match
                written, Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global buffer <: (usize & usize)
              with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        if written <>. (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global buffer <: usize)
        then
          Core.Result.Result_Err
          (Error_EncodingError
            (Core.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                        (mk_usize 2)
                        (let list =
                            [
                              "Expected that ";
                              " bytes were written but the output holds ";
                              " bytes"
                            ]
                          in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                          Rust_primitives.Hax.array_of_list 3 list)
                        (let list =
                            [
                              Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument;
                              Core.Fmt.Rt.impl__new_display #usize
                                (Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global buffer <: usize)
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
            t_Error)
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
        else
          Core.Result.Result_Ok buffer
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

/// The `SerializeBytes` trait provides a function to serialize a struct or enum.
/// The trait provides one function:
/// * `tls_serialize` that returns a byte vector
class t_SerializeBytes (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_2997919293107846837:t_Size v_Self;
  f_tls_serialize_bytes_pre:v_Self -> Type0;
  f_tls_serialize_bytes_post:
      v_Self ->
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
    -> Type0;
  f_tls_serialize_bytes:x0: v_Self
    -> Prims.Pure (Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        (f_tls_serialize_bytes_pre x0)
        (fun result -> f_tls_serialize_bytes_post x0 result)
}

/// The `Deserialize` trait defines functions to deserialize a byte slice to a
/// struct or enum.
class t_Deserialize (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_2997919293107846837:t_Size v_Self;
  f_tls_deserialize_pre:#v_R: Type0 -> {| i1: Std.Io.t_Read v_R |} -> v_R -> Type0;
  f_tls_deserialize_post:
      #v_R: Type0 ->
      {| i1: Std.Io.t_Read v_R |} ->
      v_R ->
      (v_R & Core.Result.t_Result v_Self t_Error)
    -> Type0;
  f_tls_deserialize:#v_R: Type0 -> {| i1: Std.Io.t_Read v_R |} -> x0: v_R
    -> Prims.Pure (v_R & Core.Result.t_Result v_Self t_Error)
        (f_tls_deserialize_pre #v_R #i1 x0)
        (fun result -> f_tls_deserialize_post #v_R #i1 x0 result)
}

class t_DeserializeExact (v_Self: Type0) = {
  f_tls_deserialize_exact_pre:
      #iimpl_677085834_: Type0 ->
      {| i2: Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8) |} ->
      iimpl_677085834_
    -> Type0;
  f_tls_deserialize_exact_post:
      #iimpl_677085834_: Type0 ->
      {| i2: Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8) |} ->
      iimpl_677085834_ ->
      Core.Result.t_Result v_Self t_Error
    -> Type0;
  f_tls_deserialize_exact:
      #iimpl_677085834_: Type0 ->
      {| i2: Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8) |} ->
      x0: iimpl_677085834_
    -> Prims.Pure (Core.Result.t_Result v_Self t_Error)
        (f_tls_deserialize_exact_pre #iimpl_677085834_ #i2 x0)
        (fun result -> f_tls_deserialize_exact_post #iimpl_677085834_ #i2 x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Deserialize v_T)
    : t_DeserializeExact v_T =
  {
    f_tls_deserialize_exact_pre
    =
    (fun
        (#iimpl_677085834_: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8))
        (bytes: iimpl_677085834_)
        ->
        true);
    f_tls_deserialize_exact_post
    =
    (fun
        (#iimpl_677085834_: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8))
        (bytes: iimpl_677085834_)
        (out2: Core.Result.t_Result v_T t_Error)
        ->
        true);
    f_tls_deserialize_exact
    =
    fun
      (#iimpl_677085834_: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
        i3:
        Core.Convert.t_AsRef iimpl_677085834_ (t_Slice u8))
      (bytes: iimpl_677085834_)
      ->
      let bytes:t_Slice u8 =
        Core.Convert.f_as_ref #iimpl_677085834_ #(t_Slice u8) #FStar.Tactics.Typeclasses.solve bytes
      in
      let tmp0, out1:(t_Slice u8 & Core.Result.t_Result v_T t_Error) =
        f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #(t_Slice u8) bytes
      in
      let bytes:t_Slice u8 = tmp0 in
      match out1 <: Core.Result.t_Result v_T t_Error with
      | Core.Result.Result_Ok out ->
        if ~.(Core.Slice.impl__is_empty #u8 bytes <: bool)
        then
          Core.Result.Result_Err (Error_TrailingData <: t_Error) <: Core.Result.t_Result v_T t_Error
        else Core.Result.Result_Ok out <: Core.Result.t_Result v_T t_Error
      | Core.Result.Result_Err err -> Core.Result.Result_Err err <: Core.Result.t_Result v_T t_Error
  }

/// The `DeserializeBytes` trait defines functions to deserialize a byte slice
/// to a struct or enum. In contrast to [`Deserialize`], this trait operates
/// directly on byte slices and can return any remaining bytes.
class t_DeserializeBytes (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_2997919293107846837:t_Size v_Self;
  f_tls_deserialize_bytes_pre:t_Slice u8 -> Type0;
  f_tls_deserialize_bytes_post:t_Slice u8 -> Core.Result.t_Result (v_Self & t_Slice u8) t_Error
    -> Type0;
  f_tls_deserialize_bytes:x0: t_Slice u8
    -> Prims.Pure (Core.Result.t_Result (v_Self & t_Slice u8) t_Error)
        (f_tls_deserialize_bytes_pre x0)
        (fun result -> f_tls_deserialize_bytes_post x0 result)
}

class t_DeserializeExactBytes (v_Self: Type0) = {
  f_tls_deserialize_exact_bytes_pre:t_Slice u8 -> Type0;
  f_tls_deserialize_exact_bytes_post:t_Slice u8 -> Core.Result.t_Result v_Self t_Error -> Type0;
  f_tls_deserialize_exact_bytes:x0: t_Slice u8
    -> Prims.Pure (Core.Result.t_Result v_Self t_Error)
        (f_tls_deserialize_exact_bytes_pre x0)
        (fun result -> f_tls_deserialize_exact_bytes_post x0 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_DeserializeBytes v_T)
    : t_DeserializeExactBytes v_T =
  {
    f_tls_deserialize_exact_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_exact_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result v_T t_Error) -> true);
    f_tls_deserialize_exact_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve bytes
        <:
        Core.Result.t_Result (v_T & t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok (out, remainder) ->
        if ~.(Core.Slice.impl__is_empty #u8 remainder <: bool)
        then
          Core.Result.Result_Err (Error_TrailingData <: t_Error) <: Core.Result.t_Result v_T t_Error
        else Core.Result.Result_Ok out <: Core.Result.t_Result v_T t_Error
      | Core.Result.Result_Err err -> Core.Result.Result_Err err <: Core.Result.t_Result v_T t_Error
  }

/// A 3 byte wide unsigned integer type as defined in [RFC 5246].
/// [RFC 5246]: https://datatracker.ietf.org/doc/html/rfc5246#section-4.4
type t_U24 = | U24 : t_Array u8 (mk_usize 3) -> t_U24

let impl_15: Core.Clone.t_Clone t_U24 = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Core.Marker.t_Copy t_U24

unfold
let impl_14 = impl_14'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Core.Fmt.t_Debug t_U24

unfold
let impl_16 = impl_16'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Core.Default.t_Default t_U24

unfold
let impl_17 = impl_17'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core.Marker.t_StructuralPartialEq t_U24

unfold
let impl_18 = impl_18'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Core.Cmp.t_PartialEq t_U24 t_U24

unfold
let impl_19 = impl_19'

let impl_6__MAX: t_U24 = U24 (Rust_primitives.Hax.repeat (mk_u8 255) (mk_usize 3)) <: t_U24

let impl_6__MIN: t_U24 = U24 (Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 3)) <: t_U24

let impl_6__from_be_bytes (bytes: t_Array u8 (mk_usize 3)) : t_U24 = U24 bytes <: t_U24

let impl_6__to_be_bytes (self: t_U24) : t_Array u8 (mk_usize 3) = self._0

let f_from__impl_7__v_LEN: usize = Core.Mem.size_of #usize ()

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_7: Core.Convert.t_From usize t_U24 =
  {
    f_from_pre = (fun (value: t_U24) -> true);
    f_from_post = (fun (value: t_U24) (out: usize) -> true);
    f_from
    =
    fun (value: t_U24) ->
      let usize_bytes:t_Array u8 (mk_usize 8) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 8) in
      let usize_bytes:t_Array u8 (mk_usize 8) =
        Rust_primitives.Hax.Monomorphized_update_at.update_at_range_from usize_bytes
          ({ Core.Ops.Range.f_start = f_from__impl_7__v_LEN -! mk_usize 3 <: usize }
            <:
            Core.Ops.Range.t_RangeFrom usize)
          (Core.Slice.impl__copy_from_slice #u8
              (usize_bytes.[ {
                    Core.Ops.Range.f_start = f_from__impl_7__v_LEN -! mk_usize 3 <: usize
                  }
                  <:
                  Core.Ops.Range.t_RangeFrom usize ]
                <:
                t_Slice u8)
              (value._0 <: t_Slice u8)
            <:
            t_Slice u8)
      in
      mk_usize 0
  }

let f_try_from__impl_8__v_LEN: usize = Core.Mem.size_of #usize ()

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl__from__primitives (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Size v_T)
    : t_Size (Core.Option.t_Option v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: Core.Option.t_Option v_T) -> true);
    f_tls_serialized_len_post = (fun (self: Core.Option.t_Option v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: Core.Option.t_Option v_T) ->
      mk_usize 1 +!
      (match self <: Core.Option.t_Option v_T with
        | Core.Option.Option_Some v ->
          f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve v <: usize
        | Core.Option.Option_None  -> mk_usize 0)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Size v_T)
    : t_Size (Core.Option.t_Option v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: Core.Option.t_Option v_T) -> true);
    f_tls_serialized_len_post = (fun (self: Core.Option.t_Option v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: Core.Option.t_Option v_T) ->
      f_tls_serialized_len #(Core.Option.t_Option v_T) #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Serialize v_T)
    : t_Serialize (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = i1._super_2997919293107846837;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Core.Option.t_Option v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Core.Option.t_Option v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: Core.Option.t_Option v_T)
      (writer: v_W)
      ->
      match self <: Core.Option.t_Option v_T with
      | Core.Option.Option_Some e ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            ((let list = [mk_u8 1] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              <:
              t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok written ->
            let _:Prims.unit =
              if true
              then
                let _:Prims.unit =
                  match written, mk_usize 1 <: (usize & usize) with
                  | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
                in
                ()
            in
            let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
              f_tls_serialize #v_T #FStar.Tactics.Typeclasses.solve #v_W e writer
            in
            let writer:v_W = tmp0 in
            writer,
            Core.Result.impl__map #usize
              #t_Error
              #usize
              out
              (fun l ->
                  let l:usize = l in
                  l +! mk_usize 1 <: usize)
            <:
            (v_W & Core.Result.t_Result usize t_Error)
          | Core.Result.Result_Err err ->
            writer,
            (Core.Result.Result_Err
              (Core.Convert.f_from #t_Error
                  #Std.Io.Error.t_Error
                  #FStar.Tactics.Typeclasses.solve
                  err)
              <:
              Core.Result.t_Result usize t_Error)
            <:
            (v_W & Core.Result.t_Result usize t_Error))
      | Core.Option.Option_None  ->
        let tmp0, out:(v_W & Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
          Std.Io.f_write_all #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            ((let list = [mk_u8 0] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              <:
              t_Slice u8)
        in
        let writer:v_W = tmp0 in
        match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          writer, (Core.Result.Result_Ok (mk_usize 1) <: Core.Result.t_Result usize t_Error)
          <:
          (v_W & Core.Result.t_Result usize t_Error)
        | Core.Result.Result_Err err ->
          writer,
          (Core.Result.Result_Err
            (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err
            )
            <:
            Core.Result.t_Result usize t_Error)
          <:
          (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_SerializeBytes v_T)
    : t_SerializeBytes (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = i1._super_2997919293107846837;
    f_tls_serialize_bytes_pre = (fun (self: Core.Option.t_Option v_T) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Core.Option.t_Option v_T)
        (out1: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Core.Option.t_Option v_T) ->
      match self <: Core.Option.t_Option v_T with
      | Core.Option.Option_Some e ->
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl__with_capacity #u8
            ((f_tls_serialized_len #v_T #i1._super_2997919293107846837 e <: usize) +! mk_usize 1
              <:
              usize)
        in
        let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global out (mk_u8 1)
        in
        (match
            f_tls_serialize_bytes #v_T #FStar.Tactics.Typeclasses.solve e
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
          with
          | Core.Result.Result_Ok hoist9 ->
            let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__append #u8 #Alloc.Alloc.t_Global out hoist9
            in
            Core.Result.Result_Ok out
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
      | Core.Option.Option_None  ->
        Core.Result.Result_Ok
        (Alloc.Slice.impl__into_vec #u8
            #Alloc.Alloc.t_Global
            (Rust_primitives.unsize (Rust_primitives.Hax.box_new (let list = [mk_u8 0] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Alloc.Boxed.t_Box (t_Array u8 (mk_usize 1)) Alloc.Alloc.t_Global)
              <:
              Alloc.Boxed.t_Box (t_Slice u8) Alloc.Alloc.t_Global))
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Serialize v_T)
    : t_Serialize (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = i1._super_2997919293107846837;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Core.Option.t_Option v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Core.Option.t_Option v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: Core.Option.t_Option v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #(Core.Option.t_Option v_T)
          #FStar.Tactics.Typeclasses.solve
          #v_W
          self
          writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_SerializeBytes v_T)
    : t_SerializeBytes (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = i1._super_2997919293107846837;
    f_tls_serialize_bytes_pre = (fun (self: Core.Option.t_Option v_T) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Core.Option.t_Option v_T)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Core.Option.t_Option v_T) ->
      f_tls_serialize_bytes #(Core.Option.t_Option v_T) #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Deserialize v_T)
    : t_Deserialize (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = i1._super_2997919293107846837;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let some_or_none:t_Array u8 (mk_usize 1) =
        Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 1) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes some_or_none
      in
      let bytes:v_R = tmp0 in
      let some_or_none:t_Array u8 (mk_usize 1) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        (match some_or_none.[ mk_usize 0 ] <: u8 with
          | Rust_primitives.Integers.MkInt 0 ->
            bytes,
            (Core.Result.Result_Ok (Core.Option.Option_None <: Core.Option.t_Option v_T)
              <:
              Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
            <:
            (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
          | Rust_primitives.Integers.MkInt 1 ->
            let tmp0, out:(v_R & Core.Result.t_Result v_T t_Error) =
              f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
            in
            let bytes:v_R = tmp0 in
            (match out <: Core.Result.t_Result v_T t_Error with
              | Core.Result.Result_Ok element ->
                bytes,
                (Core.Result.Result_Ok (Core.Option.Option_Some element <: Core.Option.t_Option v_T)
                  <:
                  Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
                <:
                (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
              | Core.Result.Result_Err err ->
                bytes,
                (Core.Result.Result_Err err
                  <:
                  Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
                <:
                (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error))
          | _ ->
            bytes,
            (Core.Result.Result_Err
              (Error_DecodingError
                (Core.Hint.must_use #Alloc.String.t_String
                    (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 2)
                            (mk_usize 1)
                            (let list =
                                [
                                  "Trying to decode Option<T> with ";
                                  " for option. It must be 0 for None and 1 for Some."
                                ]
                              in
                              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                              Rust_primitives.Hax.array_of_list 2 list)
                            (let list =
                                [
                                  Core.Fmt.Rt.impl__new_display #u8
                                    (some_or_none.[ mk_usize 0 ] <: u8)
                                  <:
                                  Core.Fmt.Rt.t_Argument
                                ]
                              in
                              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                              Rust_primitives.Hax.array_of_list 1 list)
                          <:
                          Core.Fmt.t_Arguments)
                      <:
                      Alloc.String.t_String))
                <:
                t_Error)
              <:
              Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
            <:
            (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error))
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
        <:
        (v_R & Core.Result.t_Result (Core.Option.t_Option v_T) t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_37: t_Size u8 =
  {
    f_tls_serialized_len_pre = (fun (self: u8) -> true);
    f_tls_serialized_len_post = (fun (self: u8) (out: usize) -> true);
    f_tls_serialized_len = fun (self: u8) -> mk_usize 1
  }


[@@ FStar.Tactics.Typeclasses.tcinstance]
assume val default_u8: Core.Default.t_Default Rust_primitives.Integers.u8

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_31: t_Deserialize u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result u8 t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let x:t_Array u8 (mk_usize 1) =
        Core.Num.impl_u8__to_be_bytes (Core.Default.f_default #u8
              #FStar.Tactics.Typeclasses.solve
              ()
            <:
            u8)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 1) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes x
      in
      let bytes:v_R = tmp0 in
      let x:t_Array u8 (mk_usize 1) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result u8 t_Error =
          Core.Result.Result_Ok (Core.Num.impl_u8__from_be_bytes x)
          <:
          Core.Result.t_Result u8 t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result u8 t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result u8 t_Error)
        <:
        (v_R & Core.Result.t_Result u8 t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_32: t_DeserializeBytes u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result (u8 & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      let len:usize = Core.Mem.size_of #u8 () in
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = len } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Error_EndOfStream <: t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok hoist14 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 (mk_usize 1))
              #Core.Array.t_TryFromSliceError
              #t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 1))
                  #FStar.Tactics.Typeclasses.solve
                  hoist14
                <:
                Core.Result.t_Result (t_Array u8 (mk_usize 1)) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Error_EndOfStream <: t_Error)
            <:
            Core.Result.t_Result (t_Array u8 (mk_usize 1)) t_Error
          with
          | Core.Result.Result_Ok out ->
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeFrom usize)
                      bytes
                      ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Error_EndOfStream <: t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok hoist17 ->
                Core.Result.Result_Ok
                (Core.Num.impl_u8__from_be_bytes out, hoist17 <: (u8 & t_Slice u8))
                <:
                Core.Result.t_Result (u8 & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err <: Core.Result.t_Result (u8 & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result (u8 & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result (u8 & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_7__from__primitives
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_DeserializeBytes v_T)
    : t_DeserializeBytes (Core.Option.t_Option v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve bytes
        <:
        Core.Result.t_Result (u8 & t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok (some_or_none, remainder) ->
        (match some_or_none <: u8 with
          | Rust_primitives.Integers.MkInt 0 ->
            Core.Result.Result_Ok
            ((Core.Option.Option_None <: Core.Option.t_Option v_T), remainder
              <:
              (Core.Option.t_Option v_T & t_Slice u8))
            <:
            Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error
          | Rust_primitives.Integers.MkInt 1 ->
            (match
                f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok (element, remainder) ->
                Core.Result.Result_Ok
                ((Core.Option.Option_Some element <: Core.Option.t_Option v_T), remainder
                  <:
                  (Core.Option.t_Option v_T & t_Slice u8))
                <:
                Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err
                <:
                Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error)
          | _ ->
            Core.Result.Result_Err
            (Error_DecodingError
              (Core.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 2)
                          (mk_usize 1)
                          (let list =
                              [
                                "Trying to decode Option<T> with ";
                                " for option. It must be 0 for None and 1 for Some."
                              ]
                            in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                            Rust_primitives.Hax.array_of_list 2 list)
                          (let list =
                              [
                                Core.Fmt.Rt.impl__new_display #u8 some_or_none
                                <:
                                Core.Fmt.Rt.t_Argument
                              ]
                            in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                        <:
                        Core.Fmt.t_Arguments)
                    <:
                    Alloc.String.t_String))
              <:
              t_Error)
            <:
            Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Core.Option.t_Option v_T & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_35: t_Serialize u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (Core.Num.impl_u8__to_be_bytes self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match written, mk_usize 1 <: (usize & usize) with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.Result_Ok written <: Core.Result.t_Result usize t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_38: t_Size u8 =
  {
    f_tls_serialized_len_pre = (fun (self: u8) -> true);
    f_tls_serialized_len_post = (fun (self: u8) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: u8) -> f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_33: t_SerializeBytes u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u8) -> true);
    f_tls_serialize_bytes_post
    =
    (fun (self: u8) (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error) ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u8) ->
      Core.Result.Result_Ok
      (Alloc.Slice.impl__to_vec #u8 (Core.Num.impl_u8__to_be_bytes self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_34: t_SerializeBytes u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u8) -> true);
    f_tls_serialize_bytes_post
    =
    (fun (self: u8) (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error) ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u8) -> f_tls_serialize_bytes #u8 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_36: t_Serialize u8 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #u8 #FStar.Tactics.Typeclasses.solve #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_45: t_Size u16 =
  {
    f_tls_serialized_len_pre = (fun (self: u16) -> true);
    f_tls_serialized_len_post = (fun (self: u16) (out: usize) -> true);
    f_tls_serialized_len = fun (self: u16) -> mk_usize 2
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_39: t_Deserialize u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result u16 t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let x:t_Array u8 (mk_usize 2) =
        Core.Num.impl_u16__to_be_bytes (Core.Default.f_default #u16
              #FStar.Tactics.Typeclasses.solve
              ()
            <:
            u16)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 2) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes x
      in
      let bytes:v_R = tmp0 in
      let x:t_Array u8 (mk_usize 2) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result u16 t_Error =
          Core.Result.Result_Ok (Core.Num.impl_u16__from_be_bytes x)
          <:
          Core.Result.t_Result u16 t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result u16 t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result u16 t_Error)
        <:
        (v_R & Core.Result.t_Result u16 t_Error)
  }

let deserialize_primitives (_: Prims.unit) : Prims.unit =
  let b:t_Slice u8 =
    (let list = [mk_u8 77; mk_u8 88; mk_u8 1; mk_u8 99] in
      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 4);
      Rust_primitives.Hax.array_of_list 4 list)
    <:
    t_Slice u8
  in
  let tmp0, out:(t_Slice u8 & Core.Result.t_Result u8 t_Error) =
    f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #(t_Slice u8) b
  in
  let b:t_Slice u8 = tmp0 in
  let a:u8 = Core.Result.impl__expect #u8 #t_Error out "Unable to tls_deserialize" in
  let _:Prims.unit =
    match
      mk_usize 1, f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve a <: (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let _:Prims.unit =
    match mk_u8 77, a <: (u8 & u8) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let tmp0, out:(t_Slice u8 & Core.Result.t_Result u8 t_Error) =
    f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #(t_Slice u8) b
  in
  let b:t_Slice u8 = tmp0 in
  let a:u8 = Core.Result.impl__expect #u8 #t_Error out "Unable to tls_deserialize" in
  let _:Prims.unit =
    match
      mk_usize 1, f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve a <: (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let _:Prims.unit =
    match mk_u8 88, a <: (u8 & u8) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let tmp0, out:(t_Slice u8 & Core.Result.t_Result u16 t_Error) =
    f_tls_deserialize #u16 #FStar.Tactics.Typeclasses.solve #(t_Slice u8) b
  in
  let b:t_Slice u8 = tmp0 in
  let a:u16 = Core.Result.impl__expect #u16 #t_Error out "Unable to tls_deserialize" in
  let _:Prims.unit =
    match
      mk_usize 2, f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve a <: (usize & usize)
    with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let _:Prims.unit =
    match mk_u16 355, a <: (u16 & u16) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let tmp0, out:(t_Slice u8 & Core.Result.t_Result u8 t_Error) =
    f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #(t_Slice u8) b
  in
  let b:t_Slice u8 = tmp0 in
  Hax_lib.v_assert (Core.Result.impl__is_err #u8 #t_Error out <: bool)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_40: t_DeserializeBytes u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result (u16 & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      let len:usize = Core.Mem.size_of #u16 () in
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = len } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Error_EndOfStream <: t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok hoist21 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 (mk_usize 2))
              #Core.Array.t_TryFromSliceError
              #t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 2))
                  #FStar.Tactics.Typeclasses.solve
                  hoist21
                <:
                Core.Result.t_Result (t_Array u8 (mk_usize 2)) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Error_EndOfStream <: t_Error)
            <:
            Core.Result.t_Result (t_Array u8 (mk_usize 2)) t_Error
          with
          | Core.Result.Result_Ok out ->
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeFrom usize)
                      bytes
                      ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Error_EndOfStream <: t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok hoist24 ->
                Core.Result.Result_Ok
                (Core.Num.impl_u16__from_be_bytes out, hoist24 <: (u16 & t_Slice u8))
                <:
                Core.Result.t_Result (u16 & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err <: Core.Result.t_Result (u16 & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result (u16 & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result (u16 & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_43: t_Serialize u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (Core.Num.impl_u16__to_be_bytes self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match written, mk_usize 2 <: (usize & usize) with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.Result_Ok written <: Core.Result.t_Result usize t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_46: t_Size u16 =
  {
    f_tls_serialized_len_pre = (fun (self: u16) -> true);
    f_tls_serialized_len_post = (fun (self: u16) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: u16) -> f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_41: t_SerializeBytes u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u16) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u16)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u16) ->
      Core.Result.Result_Ok
      (Alloc.Slice.impl__to_vec #u8 (Core.Num.impl_u16__to_be_bytes self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_42: t_SerializeBytes u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u16) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u16)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u16) -> f_tls_serialize_bytes #u16 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_44: t_Serialize u16 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #u16 #FStar.Tactics.Typeclasses.solve #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_53: t_Size t_U24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_U24) -> true);
    f_tls_serialized_len_post = (fun (self: t_U24) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_U24) -> mk_usize 3
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_47: t_Deserialize t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result t_U24 t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let x:t_Array u8 (mk_usize 3) =
        impl_6__to_be_bytes (Core.Default.f_default #t_U24 #FStar.Tactics.Typeclasses.solve ()
            <:
            t_U24)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 3) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes x
      in
      let bytes:v_R = tmp0 in
      let x:t_Array u8 (mk_usize 3) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result t_U24 t_Error =
          Core.Result.Result_Ok (impl_6__from_be_bytes x) <: Core.Result.t_Result t_U24 t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_U24 t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result t_U24 t_Error)
        <:
        (v_R & Core.Result.t_Result t_U24 t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_48: t_DeserializeBytes t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result (t_U24 & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      let len:usize = Core.Mem.size_of #t_U24 () in
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = len } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Error_EndOfStream <: t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok hoist28 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 (mk_usize 3))
              #Core.Array.t_TryFromSliceError
              #t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 3))
                  #FStar.Tactics.Typeclasses.solve
                  hoist28
                <:
                Core.Result.t_Result (t_Array u8 (mk_usize 3)) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Error_EndOfStream <: t_Error)
            <:
            Core.Result.t_Result (t_Array u8 (mk_usize 3)) t_Error
          with
          | Core.Result.Result_Ok out ->
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeFrom usize)
                      bytes
                      ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Error_EndOfStream <: t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok hoist31 ->
                Core.Result.Result_Ok (impl_6__from_be_bytes out, hoist31 <: (t_U24 & t_Slice u8))
                <:
                Core.Result.t_Result (t_U24 & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err <: Core.Result.t_Result (t_U24 & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result (t_U24 & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result (t_U24 & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_51: t_Serialize t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_U24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_U24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_U24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (impl_6__to_be_bytes self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match written, mk_usize 3 <: (usize & usize) with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.Result_Ok written <: Core.Result.t_Result usize t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_54: t_Size t_U24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_U24) -> true);
    f_tls_serialized_len_post = (fun (self: t_U24) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_U24) -> f_tls_serialized_len #t_U24 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_49: t_SerializeBytes t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_U24) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_U24)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_U24) ->
      Core.Result.Result_Ok (Alloc.Slice.impl__to_vec #u8 (impl_6__to_be_bytes self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_50: t_SerializeBytes t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_U24) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_U24)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_U24) -> f_tls_serialize_bytes #t_U24 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_52: t_Serialize t_U24 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_U24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_U24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_U24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #t_U24 #FStar.Tactics.Typeclasses.solve #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_61: t_Size u32 =
  {
    f_tls_serialized_len_pre = (fun (self: u32) -> true);
    f_tls_serialized_len_post = (fun (self: u32) (out: usize) -> true);
    f_tls_serialized_len = fun (self: u32) -> mk_usize 4
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_55: t_Deserialize u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result u32 t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let x:t_Array u8 (mk_usize 4) =
        Core.Num.impl_u32__to_be_bytes (Core.Default.f_default #u32
              #FStar.Tactics.Typeclasses.solve
              ()
            <:
            u32)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 4) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes x
      in
      let bytes:v_R = tmp0 in
      let x:t_Array u8 (mk_usize 4) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result u32 t_Error =
          Core.Result.Result_Ok (Core.Num.impl_u32__from_be_bytes x)
          <:
          Core.Result.t_Result u32 t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result u32 t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result u32 t_Error)
        <:
        (v_R & Core.Result.t_Result u32 t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_56: t_DeserializeBytes u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result (u32 & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      let len:usize = Core.Mem.size_of #u32 () in
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = len } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Error_EndOfStream <: t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok hoist35 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 (mk_usize 4))
              #Core.Array.t_TryFromSliceError
              #t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 4))
                  #FStar.Tactics.Typeclasses.solve
                  hoist35
                <:
                Core.Result.t_Result (t_Array u8 (mk_usize 4)) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Error_EndOfStream <: t_Error)
            <:
            Core.Result.t_Result (t_Array u8 (mk_usize 4)) t_Error
          with
          | Core.Result.Result_Ok out ->
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeFrom usize)
                      bytes
                      ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Error_EndOfStream <: t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok hoist38 ->
                Core.Result.Result_Ok
                (Core.Num.impl_u32__from_be_bytes out, hoist38 <: (u32 & t_Slice u8))
                <:
                Core.Result.t_Result (u32 & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err <: Core.Result.t_Result (u32 & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result (u32 & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result (u32 & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_59: t_Serialize u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (Core.Num.impl_u32__to_be_bytes self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match written, mk_usize 4 <: (usize & usize) with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.Result_Ok written <: Core.Result.t_Result usize t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_62: t_Size u32 =
  {
    f_tls_serialized_len_pre = (fun (self: u32) -> true);
    f_tls_serialized_len_post = (fun (self: u32) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: u32) -> f_tls_serialized_len #u32 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_57: t_SerializeBytes u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u32) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u32)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u32) ->
      Core.Result.Result_Ok
      (Alloc.Slice.impl__to_vec #u8 (Core.Num.impl_u32__to_be_bytes self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_58: t_SerializeBytes u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u32) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u32)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u32) -> f_tls_serialize_bytes #u32 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_60: t_Serialize u32 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #u32 #FStar.Tactics.Typeclasses.solve #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_69: t_Size u64 =
  {
    f_tls_serialized_len_pre = (fun (self: u64) -> true);
    f_tls_serialized_len_post = (fun (self: u64) (out: usize) -> true);
    f_tls_serialized_len = fun (self: u64) -> mk_usize 8
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_63: t_Deserialize u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result u64 t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let x:t_Array u8 (mk_usize 8) =
        Core.Num.impl_u64__to_be_bytes (Core.Default.f_default #u64
              #FStar.Tactics.Typeclasses.solve
              ()
            <:
            u64)
      in
      let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 8) &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes x
      in
      let bytes:v_R = tmp0 in
      let x:t_Array u8 (mk_usize 8) = tmp1 in
      match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result u64 t_Error =
          Core.Result.Result_Ok (Core.Num.impl_u64__from_be_bytes x)
          <:
          Core.Result.t_Result u64 t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result u64 t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result u64 t_Error)
        <:
        (v_R & Core.Result.t_Result u64 t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_64: t_DeserializeBytes u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out1: Core.Result.t_Result (u64 & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      let len:usize = Core.Mem.size_of #u64 () in
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = len } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Error_EndOfStream <: t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok hoist42 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 (mk_usize 8))
              #Core.Array.t_TryFromSliceError
              #t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 8))
                  #FStar.Tactics.Typeclasses.solve
                  hoist42
                <:
                Core.Result.t_Result (t_Array u8 (mk_usize 8)) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Error_EndOfStream <: t_Error)
            <:
            Core.Result.t_Result (t_Array u8 (mk_usize 8)) t_Error
          with
          | Core.Result.Result_Ok out ->
            (match
                Core.Option.impl__ok_or #(t_Slice u8)
                  #t_Error
                  (Core.Slice.impl__get #u8
                      #(Core.Ops.Range.t_RangeFrom usize)
                      bytes
                      ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                    <:
                    Core.Option.t_Option (t_Slice u8))
                  (Error_EndOfStream <: t_Error)
                <:
                Core.Result.t_Result (t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok hoist45 ->
                Core.Result.Result_Ok
                (Core.Num.impl_u64__from_be_bytes out, hoist45 <: (u64 & t_Slice u8))
                <:
                Core.Result.t_Result (u64 & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err <: Core.Result.t_Result (u64 & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result (u64 & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result (u64 & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_67: t_Serialize u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u64)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u64)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u64)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (Core.Num.impl_u64__to_be_bytes self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let _:Prims.unit =
          if true
          then
            let _:Prims.unit =
              match written, mk_usize 8 <: (usize & usize) with
              | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
            in
            ()
        in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.Result_Ok written <: Core.Result.t_Result usize t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #t_Error #Std.Io.Error.t_Error #FStar.Tactics.Typeclasses.solve err)
          <:
          Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_70: t_Size u64 =
  {
    f_tls_serialized_len_pre = (fun (self: u64) -> true);
    f_tls_serialized_len_post = (fun (self: u64) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: u64) -> f_tls_serialized_len #u64 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_65: t_SerializeBytes u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u64) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u64)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u64) ->
      Core.Result.Result_Ok
      (Alloc.Slice.impl__to_vec #u8 (Core.Num.impl_u64__to_be_bytes self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_66: t_SerializeBytes u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: u64) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: u64)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: u64) -> f_tls_serialize_bytes #u64 #FStar.Tactics.Typeclasses.solve self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_68: t_Serialize u64 =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u64)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: u64)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: u64)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #u64 #FStar.Tactics.Typeclasses.solve #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_8__from__primitives: Core.Convert.t_From t_Error Core.Array.t_TryFromSliceError =
  {
    f_from_pre = (fun (_: Core.Array.t_TryFromSliceError) -> true);
    f_from_post = (fun (_: Core.Array.t_TryFromSliceError) (out: t_Error) -> true);
    f_from = fun (_: Core.Array.t_TryFromSliceError) -> Error_InvalidInput <: t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_8: Core.Convert.t_TryFrom t_U24 usize =
  {
    f_Error = t_Error;
    f_try_from_pre = (fun (value: usize) -> true);
    f_try_from_post = (fun (value: usize) (out: Core.Result.t_Result t_U24 t_Error) -> true);
    f_try_from
    =
    fun (value: usize) ->
      if value >. ((mk_usize 1 <<! mk_i32 24 <: usize) -! mk_usize 1 <: usize)
      then
        Core.Result.Result_Err (Error_LibraryError <: t_Error) <: Core.Result.t_Result t_U24 t_Error
      else
        match
          Core.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 3))
            #FStar.Tactics.Typeclasses.solve
            ((Core.Num.impl_usize__to_be_bytes value <: t_Array u8 (mk_usize 8)).[ {
                  Core.Ops.Range.f_start = f_try_from__impl_8__v_LEN -! mk_usize 3 <: usize
                }
                <:
                Core.Ops.Range.t_RangeFrom usize ]
              <:
              t_Slice u8)
          <:
          Core.Result.t_Result (t_Array u8 (mk_usize 3)) Core.Array.t_TryFromSliceError
        with
        | Core.Result.Result_Ok hoist286 ->
          Core.Result.Result_Ok (U24 hoist286 <: t_U24) <: Core.Result.t_Result t_U24 t_Error
        | Core.Result.Result_Err err ->
          Core.Result.Result_Err
          (Core.Convert.f_from #t_Error
              #Core.Array.t_TryFromSliceError
              #FStar.Tactics.Typeclasses.solve
              err)
          <:
          Core.Result.t_Result t_U24 t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_12__from__primitives
      (#v_T #v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Size v_U)
    : t_Size (v_T & v_U) =
  {
    f_tls_serialized_len_pre = (fun (self: (v_T & v_U)) -> true);
    f_tls_serialized_len_post = (fun (self: (v_T & v_U)) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: (v_T & v_U)) ->
      (f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve self._1 <: usize) +!
      (f_tls_serialized_len #v_U #FStar.Tactics.Typeclasses.solve self._2 <: usize)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_9__from__primitives
      (#v_T #v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Deserialize v_U)
    : t_Deserialize (v_T & v_U) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (v_T & v_U) t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result v_T t_Error) =
        f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
      in
      let bytes:v_R = tmp0 in
      match out <: Core.Result.t_Result v_T t_Error with
      | Core.Result.Result_Ok hoist51 ->
        let tmp0, out:(v_R & Core.Result.t_Result v_U t_Error) =
          f_tls_deserialize #v_U #FStar.Tactics.Typeclasses.solve #v_R bytes
        in
        let bytes:v_R = tmp0 in
        (match out <: Core.Result.t_Result v_U t_Error with
          | Core.Result.Result_Ok hoist50 ->
            let hax_temp_output:Core.Result.t_Result (v_T & v_U) t_Error =
              Core.Result.Result_Ok (hoist51, hoist50 <: (v_T & v_U))
              <:
              Core.Result.t_Result (v_T & v_U) t_Error
            in
            bytes, hax_temp_output <: (v_R & Core.Result.t_Result (v_T & v_U) t_Error)
          | Core.Result.Result_Err err ->
            bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (v_T & v_U) t_Error)
            <:
            (v_R & Core.Result.t_Result (v_T & v_U) t_Error))
      | Core.Result.Result_Err err ->
        bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (v_T & v_U) t_Error)
        <:
        (v_R & Core.Result.t_Result (v_T & v_U) t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_10__from__primitives
      (#v_T #v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_DeserializeBytes v_U)
    : t_DeserializeBytes (v_T & v_U) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out: Core.Result.t_Result ((v_T & v_U) & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve bytes
        <:
        Core.Result.t_Result (v_T & t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok (first_element, remainder) ->
        (match
            f_tls_deserialize_bytes #v_U #FStar.Tactics.Typeclasses.solve remainder
            <:
            Core.Result.t_Result (v_U & t_Slice u8) t_Error
          with
          | Core.Result.Result_Ok (second_element, remainder) ->
            Core.Result.Result_Ok
            ((first_element, second_element <: (v_T & v_U)), remainder <: ((v_T & v_U) & t_Slice u8)
            )
            <:
            Core.Result.t_Result ((v_T & v_U) & t_Slice u8) t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err <: Core.Result.t_Result ((v_T & v_U) & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result ((v_T & v_U) & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_11__from__primitives
      (#v_T #v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Serialize v_U)
    : t_Serialize (v_T & v_U) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Write v_W)
        (self: (v_T & v_U))
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Write v_W)
        (self: (v_T & v_U))
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: Std.Io.t_Write v_W)
      (self: (v_T & v_U))
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #v_T #FStar.Tactics.Typeclasses.solve #v_W self._1 writer
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
          f_tls_serialize #v_U #FStar.Tactics.Typeclasses.solve #v_W self._2 writer
        in
        let writer:v_W = tmp0 in
        let hax_temp_output:Core.Result.t_Result usize t_Error =
          Core.Result.impl__map #usize
            #t_Error
            #usize
            out
            (fun l ->
                let l:usize = l in
                l +! written <: usize)
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_16__from__primitives
      (#v_T #v_U #v_V: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Size v_U)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: t_Size v_V)
    : t_Size (v_T & v_U & v_V) =
  {
    f_tls_serialized_len_pre = (fun (self: (v_T & v_U & v_V)) -> true);
    f_tls_serialized_len_post = (fun (self: (v_T & v_U & v_V)) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: (v_T & v_U & v_V)) ->
      ((f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve self._1 <: usize) +!
        (f_tls_serialized_len #v_U #FStar.Tactics.Typeclasses.solve self._2 <: usize)
        <:
        usize) +!
      (f_tls_serialized_len #v_V #FStar.Tactics.Typeclasses.solve self._3 <: usize)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_13__from__primitives
      (#v_T #v_U #v_V: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Deserialize v_U)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: t_Deserialize v_V)
    : t_Deserialize (v_T & v_U & v_V) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (v_T & v_U & v_V) t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result v_T t_Error) =
        f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
      in
      let bytes:v_R = tmp0 in
      match out <: Core.Result.t_Result v_T t_Error with
      | Core.Result.Result_Ok hoist60 ->
        let tmp0, out:(v_R & Core.Result.t_Result v_U t_Error) =
          f_tls_deserialize #v_U #FStar.Tactics.Typeclasses.solve #v_R bytes
        in
        let bytes:v_R = tmp0 in
        (match out <: Core.Result.t_Result v_U t_Error with
          | Core.Result.Result_Ok hoist59 ->
            let tmp0, out:(v_R & Core.Result.t_Result v_V t_Error) =
              f_tls_deserialize #v_V #FStar.Tactics.Typeclasses.solve #v_R bytes
            in
            let bytes:v_R = tmp0 in
            (match out <: Core.Result.t_Result v_V t_Error with
              | Core.Result.Result_Ok hoist58 ->
                let hax_temp_output:Core.Result.t_Result (v_T & v_U & v_V) t_Error =
                  Core.Result.Result_Ok (hoist60, hoist59, hoist58 <: (v_T & v_U & v_V))
                  <:
                  Core.Result.t_Result (v_T & v_U & v_V) t_Error
                in
                bytes, hax_temp_output <: (v_R & Core.Result.t_Result (v_T & v_U & v_V) t_Error)
              | Core.Result.Result_Err err ->
                bytes,
                (Core.Result.Result_Err err <: Core.Result.t_Result (v_T & v_U & v_V) t_Error)
                <:
                (v_R & Core.Result.t_Result (v_T & v_U & v_V) t_Error))
          | Core.Result.Result_Err err ->
            bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (v_T & v_U & v_V) t_Error)
            <:
            (v_R & Core.Result.t_Result (v_T & v_U & v_V) t_Error))
      | Core.Result.Result_Err err ->
        bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (v_T & v_U & v_V) t_Error)
        <:
        (v_R & Core.Result.t_Result (v_T & v_U & v_V) t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_14__from__primitives
      (#v_T #v_U #v_V: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_DeserializeBytes v_U)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: t_DeserializeBytes v_V)
    : t_DeserializeBytes (v_T & v_U & v_V) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out: Core.Result.t_Result ((v_T & v_U & v_V) & t_Slice u8) t_Error) ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve bytes
        <:
        Core.Result.t_Result (v_T & t_Slice u8) t_Error
      with
      | Core.Result.Result_Ok (first_element, remainder) ->
        (match
            f_tls_deserialize_bytes #v_U #FStar.Tactics.Typeclasses.solve remainder
            <:
            Core.Result.t_Result (v_U & t_Slice u8) t_Error
          with
          | Core.Result.Result_Ok (second_element, remainder) ->
            (match
                f_tls_deserialize_bytes #v_V #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_V & t_Slice u8) t_Error
              with
              | Core.Result.Result_Ok (third_element, remainder) ->
                Core.Result.Result_Ok
                ((first_element, second_element, third_element <: (v_T & v_U & v_V)), remainder
                  <:
                  ((v_T & v_U & v_V) & t_Slice u8))
                <:
                Core.Result.t_Result ((v_T & v_U & v_V) & t_Slice u8) t_Error
              | Core.Result.Result_Err err ->
                Core.Result.Result_Err err
                <:
                Core.Result.t_Result ((v_T & v_U & v_V) & t_Slice u8) t_Error)
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result ((v_T & v_U & v_V) & t_Slice u8) t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err <: Core.Result.t_Result ((v_T & v_U & v_V) & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_15__from__primitives
      (#v_T #v_U #v_V: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: t_Serialize v_U)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i5: t_Serialize v_V)
    : t_Serialize (v_T & v_U & v_V) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Write v_W)
        (self: (v_T & v_U & v_V))
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Write v_W)
        (self: (v_T & v_U & v_V))
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i7: Std.Io.t_Write v_W)
      (self: (v_T & v_U & v_V))
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #v_T #FStar.Tactics.Typeclasses.solve #v_W self._1 writer
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
          f_tls_serialize #v_U #FStar.Tactics.Typeclasses.solve #v_W self._2 writer
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize t_Error with
          | Core.Result.Result_Ok hoist64 ->
            let written:usize = written +! hoist64 in
            let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
              f_tls_serialize #v_V #FStar.Tactics.Typeclasses.solve #v_W self._3 writer
            in
            let writer:v_W = tmp0 in
            let hax_temp_output:Core.Result.t_Result usize t_Error =
              Core.Result.impl__map #usize
                #t_Error
                #usize
                out
                (fun l ->
                    let l:usize = l in
                    l +! written <: usize)
            in
            writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
          | Core.Result.Result_Err err ->
            writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize t_Error)
            <:
            (v_W & Core.Result.t_Result usize t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize t_Error)
        <:
        (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_17__from__primitives: t_Size Prims.unit =
  {
    f_tls_serialized_len_pre = (fun (self: Prims.unit) -> true);
    f_tls_serialized_len_post = (fun (self: Prims.unit) (out: usize) -> true);
    f_tls_serialized_len = fun (self: Prims.unit) -> mk_usize 0
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_18__from__primitives: t_Deserialize Prims.unit =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (arg_0_wild: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
        (arg_0_wild: v_R)
        (out: (v_R & Core.Result.t_Result Prims.unit t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (arg_0_wild: v_R)
      ->
      let hax_temp_output:Core.Result.t_Result Prims.unit t_Error =
        Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit t_Error
      in
      arg_0_wild, hax_temp_output <: (v_R & Core.Result.t_Result Prims.unit t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_19__from__primitives: t_DeserializeBytes Prims.unit =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun (bytes: t_Slice u8) (out: Core.Result.t_Result (Prims.unit & t_Slice u8) t_Error) -> true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      Core.Result.Result_Ok ((() <: Prims.unit), bytes <: (Prims.unit & t_Slice u8))
      <:
      Core.Result.t_Result (Prims.unit & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_20: t_Serialize Prims.unit =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: Prims.unit)
        (arg_1_wild: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: Prims.unit)
        (arg_1_wild: v_W)
        (out: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: Prims.unit)
      (arg_1_wild: v_W)
      ->
      let hax_temp_output:Core.Result.t_Result usize t_Error =
        Core.Result.Result_Ok (mk_usize 0) <: Core.Result.t_Result usize t_Error
      in
      arg_1_wild, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_21 (#v_T: Type0) : t_Size (Core.Marker.t_PhantomData v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: Core.Marker.t_PhantomData v_T) -> true);
    f_tls_serialized_len_post = (fun (self: Core.Marker.t_PhantomData v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: Core.Marker.t_PhantomData v_T) -> mk_usize 0
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_22 (#v_T: Type0) : t_Deserialize (Core.Marker.t_PhantomData v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Read v_R)
        (arg_0_wild: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Read v_R)
        (arg_0_wild: v_R)
        (out: (v_R & Core.Result.t_Result (Core.Marker.t_PhantomData v_T) t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Read v_R)
      (arg_0_wild: v_R)
      ->
      let hax_temp_output:Core.Result.t_Result (Core.Marker.t_PhantomData v_T) t_Error =
        Core.Result.Result_Ok (Core.Marker.PhantomData <: Core.Marker.t_PhantomData v_T)
        <:
        Core.Result.t_Result (Core.Marker.t_PhantomData v_T) t_Error
      in
      arg_0_wild, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (Core.Marker.t_PhantomData v_T) t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_23 (#v_T: Type0) : t_DeserializeBytes (Core.Marker.t_PhantomData v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (Core.Marker.t_PhantomData v_T & t_Slice u8) t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      Core.Result.Result_Ok
      ((Core.Marker.PhantomData <: Core.Marker.t_PhantomData v_T), bytes
        <:
        (Core.Marker.t_PhantomData v_T & t_Slice u8))
      <:
      Core.Result.t_Result (Core.Marker.t_PhantomData v_T & t_Slice u8) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_24 (#v_T: Type0) : t_Serialize (Core.Marker.t_PhantomData v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Write v_W)
        (self: Core.Marker.t_PhantomData v_T)
        (arg_1_wild: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Write v_W)
        (self: Core.Marker.t_PhantomData v_T)
        (arg_1_wild: v_W)
        (out: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Std.Io.t_Write v_W)
      (self: Core.Marker.t_PhantomData v_T)
      (arg_1_wild: v_W)
      ->
      let hax_temp_output:Core.Result.t_Result usize t_Error =
        Core.Result.Result_Ok (mk_usize 0) <: Core.Result.t_Result usize t_Error
      in
      arg_1_wild, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_25 (#v_T: Type0) : t_SerializeBytes (Core.Marker.t_PhantomData v_T) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: Core.Marker.t_PhantomData v_T) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Core.Marker.t_PhantomData v_T)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Core.Marker.t_PhantomData v_T) ->
      Core.Result.Result_Ok (Alloc.Vec.impl__new #u8 ())
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_26 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Size v_T)
    : t_Size (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) =
  {
    f_tls_serialized_len_pre = (fun (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialized_len_post
    =
    (fun (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) ->
      f_tls_serialized_len #v_T
        #FStar.Tactics.Typeclasses.solve
        (Core.Convert.f_as_ref #(Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
            #v_T
            #FStar.Tactics.Typeclasses.solve
            self
          <:
          v_T)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_27 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Serialize v_T)
    : t_Serialize (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize t_Error) =
        f_tls_serialize #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_W
          (Core.Convert.f_as_ref #(Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
              #v_T
              #FStar.Tactics.Typeclasses.solve
              self
            <:
            v_T)
          writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_28 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_SerializeBytes v_T)
    : t_SerializeBytes (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) ->
      f_tls_serialize_bytes #v_T
        #FStar.Tactics.Typeclasses.solve
        (Core.Convert.f_as_ref #(Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
            #v_T
            #FStar.Tactics.Typeclasses.solve
            self
          <:
          v_T)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_29 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_Deserialize v_T)
    : t_Deserialize (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result v_T t_Error) =
        f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) t_Error
      =
        Core.Result.impl__map #v_T
          #t_Error
          #(Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global)
          out
          Alloc.Boxed.impl__new
      in
      bytes, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_30 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: t_DeserializeBytes v_T)
    : t_DeserializeBytes (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out:
          Core.Result.t_Result (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global & t_Slice u8) t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      Core.Result.impl__map #(v_T & t_Slice u8)
        #t_Error
        #(Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global & t_Slice u8)
        (f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve bytes
          <:
          Core.Result.t_Result (v_T & t_Slice u8) t_Error)
        (fun temp_0_ ->
            let v, r:(v_T & t_Slice u8) = temp_0_ in
            v, r <: (Alloc.Boxed.t_Box v_T Alloc.Alloc.t_Global & t_Slice u8))
  }
