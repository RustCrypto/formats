module Tls_codec.Quic_vec.Rw
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Std.Io in
  let open Tls_codec in
  let open Tls_codec.Quic_vec in
  ()

/// Read the length of a variable-length vector.
/// This function assumes that the reader is at the start of a variable length
/// vector and returns an error if there's not a single byte to read.
/// The length and number of bytes read are returned.
let read_length
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error) =
  let len_len_byte:t_Array u8 (mk_usize 1) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1) in
  let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 1) &
    Core.Result.t_Result usize Std.Io.Error.t_Error) =
    Std.Io.f_read #v_R #FStar.Tactics.Typeclasses.solve bytes len_len_byte
  in
  let bytes:v_R = tmp0 in
  let len_len_byte:t_Array u8 (mk_usize 1) = tmp1 in
  match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
  | Core.Result.Result_Ok hoist89 ->
    if hoist89 =. mk_usize 0
    then
      bytes,
      (Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
        <:
        Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
      <:
      (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
    else
      let len_len_byte:u8 = len_len_byte.[ mk_usize 0 ] in
      (match
          Tls_codec.Quic_vec.calculate_length len_len_byte
          <:
          Core.Result.t_Result (usize & usize) Tls_codec.t_Error
        with
        | Core.Result.Result_Ok (length, len_len) ->
          (match
              Rust_primitives.Hax.Folds.fold_range_return (mk_usize 1)
                len_len
                (fun temp_0_ temp_1_ ->
                    let bytes, length:(v_R & usize) = temp_0_ in
                    let _:usize = temp_1_ in
                    true)
                (bytes, length <: (v_R & usize))
                (fun temp_0_ temp_1_ ->
                    let bytes, length:(v_R & usize) = temp_0_ in
                    let _:usize = temp_1_ in
                    let next:t_Array u8 (mk_usize 1) =
                      Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1)
                    in
                    let tmp0, tmp1, out:(v_R & t_Array u8 (mk_usize 1) &
                      Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
                      Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes next
                    in
                    let bytes:v_R = tmp0 in
                    let next:t_Array u8 (mk_usize 1) = tmp1 in
                    match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
                    | Core.Result.Result_Ok _ ->
                      let length:usize =
                        (length <<! mk_i32 8 <: usize) +!
                        (Core.Convert.f_from #usize
                            #u8
                            #FStar.Tactics.Typeclasses.solve
                            (next.[ mk_usize 0 ] <: u8)
                          <:
                          usize)
                      in
                      Core.Ops.Control_flow.ControlFlow_Continue (bytes, length <: (v_R & usize))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
                            (Prims.unit & (v_R & usize))) (v_R & usize)
                    | Core.Result.Result_Err err ->
                      Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Ops.Control_flow.ControlFlow_Break
                        (bytes,
                          (Core.Result.Result_Err
                            (Core.Convert.f_from #Tls_codec.t_Error
                                #Std.Io.Error.t_Error
                                #FStar.Tactics.Typeclasses.solve
                                err)
                            <:
                            Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
                          <:
                          (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
                          (Prims.unit & (v_R & usize)))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
                            (Prims.unit & (v_R & usize))) (v_R & usize))
              <:
              Core.Ops.Control_flow.t_ControlFlow
                (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error) (v_R & usize)
            with
            | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
            | Core.Ops.Control_flow.ControlFlow_Continue (bytes, length) ->
              match
                Tls_codec.Quic_vec.check_min_length length len_len
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
                  Core.Result.Result_Ok (length, len_len <: (usize & usize))
                  <:
                  Core.Result.t_Result (usize & usize) Tls_codec.t_Error
                in
                bytes, hax_temp_output
                <:
                (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                bytes,
                (Core.Result.Result_Err err
                  <:
                  Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
                <:
                (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error))
        | Core.Result.Result_Err err ->
          bytes,
          (Core.Result.Result_Err err <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes,
    (Core.Result.Result_Err
      (Core.Convert.f_from #Tls_codec.t_Error
          #Std.Io.Error.t_Error
          #FStar.Tactics.Typeclasses.solve
          err)
      <:
      Core.Result.t_Result (usize & usize) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
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
        (out1:
          (v_R & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error) =
        read_length #v_R bytes
      in
      let bytes:v_R = tmp0 in
      match out <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error with
      | Core.Result.Result_Ok (length, len_len) ->
        if length =. mk_usize 0
        then
          bytes,
          (Core.Result.Result_Ok (Alloc.Vec.impl__new #v_T ())
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error)
        else
          let result:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global = Alloc.Vec.impl__new #v_T () in
          let read:usize = len_len in
          (match
              Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
                    let bytes, read, result:(v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    =
                      temp_0_
                    in
                    (read -! len_len <: usize) <. length <: bool)
                (fun temp_0_ ->
                    let bytes, read, result:(v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    =
                      temp_0_
                    in
                    true)
                (fun temp_0_ ->
                    let bytes, read, result:(v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    =
                      temp_0_
                    in
                    Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
                (bytes, read, result <: (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
                (fun temp_0_ ->
                    let bytes, read, result:(v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    =
                      temp_0_
                    in
                    let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                      Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
                    in
                    let bytes:v_R = tmp0 in
                    match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
                    | Core.Result.Result_Ok element ->
                      let read:usize =
                        read +!
                        (Tls_codec.f_tls_serialized_len #v_T
                            #i1._super_6186925850915422136
                            element
                          <:
                          usize)
                      in
                      let result:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
                        Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global result element
                      in
                      Core.Ops.Control_flow.ControlFlow_Continue
                      (bytes, read, result
                        <:
                        (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (v_R &
                              Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                                Tls_codec.t_Error)
                            (Prims.unit & (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                        (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                    | Core.Result.Result_Err err ->
                      Core.Ops.Control_flow.ControlFlow_Break
                      (Core.Ops.Control_flow.ControlFlow_Break
                        (bytes,
                          (Core.Result.Result_Err err
                            <:
                            Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                              Tls_codec.t_Error)
                          <:
                          (v_R &
                            Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                              Tls_codec.t_Error))
                        <:
                        Core.Ops.Control_flow.t_ControlFlow
                          (v_R &
                            Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                              Tls_codec.t_Error)
                          (Prims.unit & (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (Core.Ops.Control_flow.t_ControlFlow
                            (v_R &
                              Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                                Tls_codec.t_Error)
                            (Prims.unit & (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)))
                        (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global))
              <:
              Core.Ops.Control_flow.t_ControlFlow
                (v_R &
                  Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error)
                (v_R & usize & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            with
            | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
            | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
              let hax_temp_output:Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
                Tls_codec.t_Error =
                Core.Result.Result_Ok result
                <:
                Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error
              in
              bytes, hax_temp_output
              <:
              (v_R &
                Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err err
          <:
          Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error)
        <:
        (v_R & Core.Result.t_Result (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) Tls_codec.t_Error)
  }

let write_length
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (writer: v_W)
      (content_length: usize)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    Tls_codec.Quic_vec.write_variable_length content_length
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok buf ->
    let buf_len:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global buf in
    let tmp0, out:(v_W & Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
      Std.Io.f_write_all #v_W
        #FStar.Tactics.Typeclasses.solve
        writer
        (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            buf
          <:
          t_Slice u8)
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
      | Core.Result.Result_Ok _ ->
        let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
          Core.Result.Result_Ok buf_len <: Core.Result.t_Result usize Tls_codec.t_Error
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Fmt.t_Debug v_T)
    : Tls_codec.t_Serialize (t_Slice v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_Slice v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_Slice v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_Slice v_T)
      (writer: v_W)
      ->
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
              (Tls_codec.f_tls_serialized_len #v_T #i1._super_6186925850915422136 e <: usize)
              <:
              usize)
      in
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        write_length #v_W writer content_length
      in
      let writer:v_W = tmp0 in
      match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok len_len ->
        let written:usize = mk_usize 0 in
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T self <: Core.Slice.Iter.t_Iter v_T)
                <:
                Core.Slice.Iter.t_Iter v_T)
              (writer, written <: (v_W & usize))
              (fun temp_0_ e ->
                  let writer, written:(v_W & usize) = temp_0_ in
                  let e:v_T = e in
                  let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
                    Tls_codec.f_tls_serialize #v_T #FStar.Tactics.Typeclasses.solve #v_W e writer
                  in
                  let writer:v_W = tmp0 in
                  match out <: Core.Result.t_Result usize Tls_codec.t_Error with
                  | Core.Result.Result_Ok hoist99 ->
                    let written:usize = written +! hoist99 in
                    Core.Ops.Control_flow.ControlFlow_Continue (writer, written <: (v_W & usize))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
                          (Prims.unit & (v_W & usize))) (v_W & usize)
                  | Core.Result.Result_Err err ->
                    Core.Ops.Control_flow.ControlFlow_Break
                    (Core.Ops.Control_flow.ControlFlow_Break
                      (writer,
                        (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
                        <:
                        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
                      <:
                      Core.Ops.Control_flow.t_ControlFlow
                        (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
                        (Prims.unit & (v_W & usize)))
                    <:
                    Core.Ops.Control_flow.t_ControlFlow
                      (Core.Ops.Control_flow.t_ControlFlow
                          (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
                          (Prims.unit & (v_W & usize))) (v_W & usize))
            <:
            Core.Ops.Control_flow.t_ControlFlow (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              (v_W & usize)
          with
          | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
          | Core.Ops.Control_flow.ControlFlow_Continue (writer, written) ->
            if written <>. content_length
            then
              writer,
              (Core.Result.Result_Err (Tls_codec.Error_LibraryError <: Tls_codec.t_Error)
                <:
                Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            else
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok (content_length +! len_len)
                <:
                Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Fmt.t_Debug v_T)
    : Tls_codec.t_Serialize (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        Tls_codec.f_tls_serialize #(t_Slice v_T)
          #FStar.Tactics.Typeclasses.solve
          #v_W
          (Alloc.Vec.impl_1__as_slice #v_T #Alloc.Alloc.t_Global self <: t_Slice v_T)
          writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }
