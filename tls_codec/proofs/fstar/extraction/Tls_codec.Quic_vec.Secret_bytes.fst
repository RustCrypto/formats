module Tls_codec.Quic_vec.Secret_bytes
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Std.Io in
  let open Tls_codec in
  let open Tls_codec.Quic_vec in
  let open Tls_codec.Quic_vec.Rw_bytes in
  ()

/// A wrapper struct around [`VLBytes`] that implements [`ZeroizeOnDrop`]. It
/// behaves just like [`VLBytes`], except that it doesn't allow conversion into
/// a [`Vec<u8>`].
type t_SecretVLBytes = | SecretVLBytes : Tls_codec.Quic_vec.t_VLBytes -> t_SecretVLBytes

let impl_4: Core.Clone.t_Clone t_SecretVLBytes =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core.Marker.t_StructuralPartialEq t_SecretVLBytes

unfold
let impl_5 = impl_5'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Core.Cmp.t_PartialEq t_SecretVLBytes t_SecretVLBytes

unfold
let impl_6 = impl_6'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core.Cmp.t_Eq t_SecretVLBytes

unfold
let impl_7 = impl_7'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Core.Hash.t_Hash t_SecretVLBytes

unfold
let impl_8 = impl_8'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core.Cmp.t_PartialOrd t_SecretVLBytes t_SecretVLBytes

unfold
let impl_10 = impl_10'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Core.Cmp.t_Ord t_SecretVLBytes

unfold
let impl_9 = impl_9'

/// Generate a new variable-length byte vector that implements
/// [`ZeroizeOnDrop`].
assume
val impl_SecretVLBytes__new': vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> t_SecretVLBytes

unfold
let impl_SecretVLBytes__new = impl_SecretVLBytes__new'

assume
val impl_SecretVLBytes__vec': self: t_SecretVLBytes -> t_Slice u8

unfold
let impl_SecretVLBytes__vec = impl_SecretVLBytes__vec'

(* [@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_12: Core.Fmt.t_Debug t_SecretVLBytes =
  {
    f_fmt_pre = (fun (self: t_SecretVLBytes) (f: Core.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_SecretVLBytes)
        (f: Core.Fmt.t_Formatter)
        (out1: (Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_SecretVLBytes) (f: Core.Fmt.t_Formatter) ->
      let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
        Core.Fmt.impl_11__write_fmt f
          (Core.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
              (mk_usize 0)
              (let list = ["SecretVLBytes { "] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
              (let list:Prims.list Core.Fmt.Rt.t_Argument = [] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
                Rust_primitives.Hax.array_of_list 0 list)
            <:
            Core.Fmt.t_Arguments)
      in
      let f:Core.Fmt.t_Formatter = tmp0 in
      match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
      | Core.Result.Result_Ok _ ->
        let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error) =
          Tls_codec.Quic_vec.write_hex f (impl_SecretVLBytes__vec self <: t_Slice u8)
        in
        let f:Core.Fmt.t_Formatter = tmp0 in
        (match out <: Core.Result.t_Result Prims.unit Core.Fmt.t_Error with
          | Core.Result.Result_Ok _ ->
            let tmp0, out:(Core.Fmt.t_Formatter & Core.Result.t_Result Prims.unit Core.Fmt.t_Error)
            =
              Core.Fmt.impl_11__write_fmt f
                (Core.Fmt.Rt.impl_1__new_const (mk_usize 1)
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
  } *)

/// Get a reference to the vlbytes's vec.
let impl_SecretVLBytes__as_slice (self: t_SecretVLBytes) : t_Slice u8 =
  Core.Convert.f_as_ref #(t_Slice u8)
    #(t_Slice u8)
    #FStar.Tactics.Typeclasses.solve
    (impl_SecretVLBytes__vec self <: t_Slice u8)

/// Add an element to this.
/// Remove the last element.
let impl_SecretVLBytes__pop (self: t_SecretVLBytes) : (t_SecretVLBytes & Core.Option.t_Option u8) =
  let hax_temp_output:Core.Option.t_Option u8 =
    Core.Option.Option_None <: Core.Option.t_Option u8
  in
  self, hax_temp_output <: (t_SecretVLBytes & Core.Option.t_Option u8)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_14: Core.Convert.t_From t_SecretVLBytes (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post
    =
    (fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_SecretVLBytes) -> true);
    f_from = fun (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_SecretVLBytes__new vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_15: Core.Convert.t_From t_SecretVLBytes (t_Slice u8) =
  {
    f_from_pre = (fun (slice: t_Slice u8) -> true);
    f_from_post = (fun (slice: t_Slice u8) (out: t_SecretVLBytes) -> true);
    f_from
    =
    fun (slice: t_Slice u8) ->
      impl_SecretVLBytes__new (Alloc.Slice.impl__to_vec #u8 slice
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_16 (v_N: usize) : Core.Convert.t_From t_SecretVLBytes (t_Array u8 v_N) =
  {
    f_from_pre = (fun (slice: t_Array u8 v_N) -> true);
    f_from_post = (fun (slice: t_Array u8 v_N) (out: t_SecretVLBytes) -> true);
    f_from
    =
    fun (slice: t_Array u8 v_N) ->
      impl_SecretVLBytes__new (Alloc.Slice.impl__to_vec #u8 (slice <: t_Slice u8)
          <:
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_17: Core.Convert.t_AsRef t_SecretVLBytes (t_Slice u8) =
  {
    f_as_ref_pre = (fun (self: t_SecretVLBytes) -> true);
    f_as_ref_post = (fun (self: t_SecretVLBytes) (out: t_Slice u8) -> true);
    f_as_ref = fun (self: t_SecretVLBytes) -> impl_SecretVLBytes__vec self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Tls_codec.t_Size t_SecretVLBytes =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretVLBytes) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretVLBytes) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretVLBytes) ->
      Tls_codec.f_tls_serialized_len #Tls_codec.Quic_vec.t_VLBytes
        #FStar.Tactics.Typeclasses.solve
        self._0
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Tls_codec.t_DeserializeBytes t_SecretVLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_SecretVLBytes & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        Tls_codec.f_tls_deserialize_bytes #Tls_codec.Quic_vec.t_VLBytes
          #FStar.Tactics.Typeclasses.solve
          bytes
        <:
        Core.Result.t_Result (Tls_codec.Quic_vec.t_VLBytes & t_Slice u8) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok (bytes, remainder) ->
        Core.Result.Result_Ok
        ((SecretVLBytes bytes <: t_SecretVLBytes), remainder <: (t_SecretVLBytes & t_Slice u8))
        <:
        Core.Result.t_Result (t_SecretVLBytes & t_Slice u8) Tls_codec.t_Error
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (t_SecretVLBytes & t_Slice u8) Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Tls_codec.t_Serialize t_SecretVLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_SecretVLBytes)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_SecretVLBytes)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_SecretVLBytes)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        Tls_codec.f_tls_serialize #Tls_codec.Quic_vec.t_VLBytes
          #FStar.Tactics.Typeclasses.solve
          #v_W
          self._0
          writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Tls_codec.t_Deserialize t_SecretVLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
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
        (out1: (v_R & Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error) =
        Tls_codec.f_tls_deserialize #Tls_codec.Quic_vec.t_VLBytes
          #FStar.Tactics.Typeclasses.solve
          #v_R
          bytes
      in
      let bytes:v_R = tmp0 in
      match out <: Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error with
      | Core.Result.Result_Ok hoist112 ->
        let hax_temp_output:Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error =
          Core.Result.Result_Ok (SecretVLBytes hoist112 <: t_SecretVLBytes)
          <:
          Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err err <: Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error)
        <:
        (v_R & Core.Result.t_Result t_SecretVLBytes Tls_codec.t_Error)
  }
