module Tls_codec.Arrays
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Std.Io in
  let open Tls_codec in
  ()

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4 (v_LEN: usize) : Tls_codec.t_Size (t_Array u8 v_LEN) =
  {
    f_tls_serialized_len_pre = (fun (self: t_Array u8 v_LEN) -> true);
    f_tls_serialized_len_post = (fun (self: t_Array u8 v_LEN) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_Array u8 v_LEN) -> v_LEN
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl (v_LEN: usize) : Tls_codec.t_Serialize (t_Array u8 v_LEN) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_Array u8 v_LEN)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_Array u8 v_LEN)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_Array u8 v_LEN)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
        Std.Io.f_write #v_W #FStar.Tactics.Typeclasses.solve writer (self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
      | Core.Result.Result_Ok written ->
        let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
          if written =. v_LEN
          then Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
          else
            Core.Result.Result_Err
            (Tls_codec.Error_InvalidWriteLength
              (Core.Hint.must_use #Alloc.String.t_String
                  (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                          (mk_usize 2)
                          (let list =
                              ["Expected to write "; " bytes but only "; " were written."]
                            in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                            Rust_primitives.Hax.array_of_list 3 list)
                          (let list =
                              [
                                Core.Fmt.Rt.impl__new_display #usize v_LEN <: Core.Fmt.Rt.t_Argument;
                                Core.Fmt.Rt.impl__new_display #usize written
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
            Core.Result.t_Result usize Tls_codec.t_Error
        in
        writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        writer,
        (Core.Result.Result_Err
          (Core.Convert.f_from #Tls_codec.t_Error
              #Std.Io.Error.t_Error
              #FStar.Tactics.Typeclasses.solve
              err)
          <:
          Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1 (v_LEN: usize) : Tls_codec.t_Deserialize (t_Array u8 v_LEN) =
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
        (out2: (v_R & Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let out:t_Array u8 v_LEN = Rust_primitives.Hax.repeat (mk_u8 0) v_LEN in
      let tmp0, tmp1, out1:(v_R & t_Array u8 v_LEN &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes out
      in
      let bytes:v_R = tmp0 in
      let out:t_Array u8 v_LEN = tmp1 in
      match out1 <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error =
          Core.Result.Result_Ok out <: Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err
          (Core.Convert.f_from #Tls_codec.t_Error
              #Std.Io.Error.t_Error
              #FStar.Tactics.Typeclasses.solve
              err)
          <:
          Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error)
        <:
        (v_R & Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2 (v_LEN: usize) : Tls_codec.t_DeserializeBytes (t_Array u8 v_LEN) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out1: Core.Result.t_Result (t_Array u8 v_LEN & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) ->
      match
        Core.Option.impl__ok_or #(t_Slice u8)
          #Tls_codec.t_Error
          (Core.Slice.impl__get #u8
              #(Core.Ops.Range.t_RangeTo usize)
              bytes
              ({ Core.Ops.Range.f_end = v_LEN } <: Core.Ops.Range.t_RangeTo usize)
            <:
            Core.Option.t_Option (t_Slice u8))
          (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
        <:
        Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok hoist3 ->
        (match
            Core.Result.impl__map_err #(t_Array u8 v_LEN)
              #Core.Array.t_TryFromSliceError
              #Tls_codec.t_Error
              (Core.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 v_LEN)
                  #FStar.Tactics.Typeclasses.solve
                  hoist3
                <:
                Core.Result.t_Result (t_Array u8 v_LEN) Core.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core.Array.t_TryFromSliceError = temp_0_ in
                  Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
            <:
            Core.Result.t_Result (t_Array u8 v_LEN) Tls_codec.t_Error
          with
          | Core.Result.Result_Ok out ->
            Core.Result.Result_Ok
            (out, bytes.[ { Core.Ops.Range.f_start = v_LEN } <: Core.Ops.Range.t_RangeFrom usize ]
              <:
              (t_Array u8 v_LEN & t_Slice u8))
            <:
            Core.Result.t_Result (t_Array u8 v_LEN & t_Slice u8) Tls_codec.t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (t_Array u8 v_LEN & t_Slice u8) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (t_Array u8 v_LEN & t_Slice u8) Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3 (v_LEN: usize) : Tls_codec.t_SerializeBytes (t_Array u8 v_LEN) =
  {
    _super_2997919293107846837 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_Array u8 v_LEN) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_Array u8 v_LEN)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_Array u8 v_LEN) ->
      Core.Result.Result_Ok (Alloc.Slice.impl__to_vec #u8 (self <: t_Slice u8))
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
  }
