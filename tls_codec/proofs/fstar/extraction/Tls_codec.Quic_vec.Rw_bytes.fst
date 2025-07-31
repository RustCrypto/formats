module Tls_codec.Quic_vec.Rw_bytes
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

let tls_serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
      (writer: v_W)
      (bytes: t_Slice u8)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  let content_length:usize = Core.Slice.impl__len #u8 bytes in
  let _:Prims.unit =
    if ~.false
    then
      let _:Prims.unit =
        if true
        then
          let _:Prims.unit =
            if ~.((cast (content_length <: usize) <: u64) <=. Tls_codec.Quic_vec.v_MAX_LEN <: bool)
            then
              let args:(usize & u64) =
                content_length, Tls_codec.Quic_vec.v_MAX_LEN <: (usize & u64)
              in
              let args:t_Array Core.Fmt.Rt.t_Argument (mk_usize 2) =
                let list =
                  [
                    Core.Fmt.Rt.impl__new_display #usize args._1;
                    Core.Fmt.Rt.impl__new_display #u64 args._2
                  ]
                in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                Rust_primitives.Hax.array_of_list 2 list
              in
              Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_1__new_v1
                        (mk_usize 2)
                        (mk_usize 2)
                        (let list = ["Vector can't be encoded. It's too large. "; " >= "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                          Rust_primitives.Hax.array_of_list 2 list)
                        args
                      <:
                      Core.Fmt.t_Arguments)
                  <:
                  Rust_primitives.Hax.t_Never)
          in
          ()
      in
      ()
  in
  if (cast (content_length <: usize) <: u64) >. Tls_codec.Quic_vec.v_MAX_LEN
  then
    writer,
    (Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
      <:
      Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  else
    match
      Tls_codec.Quic_vec.write_variable_length content_length
      <:
      Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
    with
    | Core.Result.Result_Ok length_bytes ->
      let len_len:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_bytes in
      let tmp0, out:(v_W & Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_write_all #v_W
          #FStar.Tactics.Typeclasses.solve
          writer
          (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              length_bytes
            <:
            t_Slice u8)
      in
      let writer:v_W = tmp0 in
      (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          let tmp0, out:(v_W & Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
            Std.Io.f_write_all #v_W #FStar.Tactics.Typeclasses.solve writer bytes
          in
          let writer:v_W = tmp0 in
          (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok (content_length +! len_len)
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
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
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
let impl: Tls_codec.t_Serialize Tls_codec.Quic_vec.t_VLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLBytes)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLBytes)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
      (self: Tls_codec.Quic_vec.t_VLBytes)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        tls_serialize_bytes #v_W
          writer
          (Tls_codec.Quic_vec.impl_VLBytes__as_slice self <: t_Slice u8)
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Tls_codec.t_Serialize Tls_codec.Quic_vec.t_VLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLBytes)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLBytes)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
      (self: Tls_codec.Quic_vec.t_VLBytes)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        Tls_codec.f_tls_serialize #Tls_codec.Quic_vec.t_VLBytes
          #FStar.Tactics.Typeclasses.solve
          #v_W
          self
          writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_2: Tls_codec.t_Deserialize Tls_codec.Quic_vec.t_VLBytes =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (usize & usize) Tls_codec.t_Error) =
        Tls_codec.Quic_vec.Rw.read_length #v_R bytes
      in
      let bytes:v_R = tmp0 in
      match out <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error with
      | Core.Result.Result_Ok (length, _) ->
        if length =. mk_usize 0
        then
          bytes,
          (Core.Result.Result_Ok
            (Tls_codec.Quic_vec.impl_VLBytes__new (Alloc.Vec.impl__new #u8 ()
                  <:
                  Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            <:
            Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
        else
          let _:Prims.unit =
            if ~.false
            then
              let _:Prims.unit =
                if true
                then
                  let _:Prims.unit =
                    if ~.(length <=. (cast (Tls_codec.Quic_vec.v_MAX_LEN <: u64) <: usize) <: bool)
                    then
                      let args:(usize & u64) =
                        length, Tls_codec.Quic_vec.v_MAX_LEN <: (usize & u64)
                      in
                      let args:t_Array Core.Fmt.Rt.t_Argument (mk_usize 2) =
                        let list =
                          [
                            Core.Fmt.Rt.impl__new_display #usize args._1;
                            Core.Fmt.Rt.impl__new_display #u64 args._2
                          ]
                        in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                        Rust_primitives.Hax.array_of_list 2 list
                      in
                      Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_1__new_v1
                                (mk_usize 3)
                                (mk_usize 2)
                                (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                                  Rust_primitives.Hax.array_of_list 3 list)
                                args
                              <:
                              Core.Fmt.t_Arguments)
                          <:
                          Rust_primitives.Hax.t_Never)
                  in
                  ()
              in
              ()
          in
          if length >. (cast (Tls_codec.Quic_vec.v_MAX_LEN <: u64) <: usize)
          then
            let args:(usize & u64) = length, Tls_codec.Quic_vec.v_MAX_LEN <: (usize & u64) in
            let args:t_Array Core.Fmt.Rt.t_Argument (mk_usize 2) =
              let list =
                [
                  Core.Fmt.Rt.impl__new_display #usize args._1;
                  Core.Fmt.Rt.impl__new_display #u64 args._2
                ]
              in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
              Rust_primitives.Hax.array_of_list 2 list
            in
            bytes,
            (Core.Result.Result_Err
              (Tls_codec.Error_DecodingError
                (Core.Hint.must_use #Alloc.String.t_String
                    (Alloc.Fmt.format (Core.Fmt.Rt.impl_1__new_v1 (mk_usize 3)
                            (mk_usize 2)
                            (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                              Rust_primitives.Hax.array_of_list 3 list)
                            args
                          <:
                          Core.Fmt.t_Arguments)
                      <:
                      Alloc.String.t_String))
                <:
                Tls_codec.t_Error)
              <:
              Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
            <:
            (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
          else
            let result:Tls_codec.Quic_vec.t_VLBytes =
              { Tls_codec.Quic_vec.f_vec = Alloc.Vec.from_elem #u8 (mk_u8 0) length }
              <:
              Tls_codec.Quic_vec.t_VLBytes
            in
            let tmp0, tmp1, out:(v_R & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
              Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
              Std.Io.f_read_exact #v_R
                #FStar.Tactics.Typeclasses.solve
                bytes
                result.Tls_codec.Quic_vec.f_vec
            in
            let bytes:v_R = tmp0 in
            let result:Tls_codec.Quic_vec.t_VLBytes =
              { result with Tls_codec.Quic_vec.f_vec = tmp1 } <: Tls_codec.Quic_vec.t_VLBytes
            in
            (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes
                  Tls_codec.t_Error =
                  Core.Result.Result_Ok result
                  <:
                  Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error
                in
                bytes, hax_temp_output
                <:
                (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                bytes,
                (Core.Result.Result_Err
                  (Core.Convert.f_from #Tls_codec.t_Error
                      #Std.Io.Error.t_Error
                      #FStar.Tactics.Typeclasses.solve
                      err)
                  <:
                  Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
                <:
                (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        bytes,
        (Core.Result.Result_Err err
          <:
          Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
        <:
        (v_R & Core.Result.t_Result Tls_codec.Quic_vec.t_VLBytes Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Tls_codec.t_Serialize Tls_codec.Quic_vec.t_VLByteSlice =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLByteSlice)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLByteSlice)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
      (self: Tls_codec.Quic_vec.t_VLByteSlice)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        tls_serialize_bytes #v_W writer self.Tls_codec.Quic_vec._0
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4: Tls_codec.t_Serialize Tls_codec.Quic_vec.t_VLByteSlice =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLByteSlice)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
        (self: Tls_codec.Quic_vec.t_VLByteSlice)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Std.Io.t_Write v_W)
      (self: Tls_codec.Quic_vec.t_VLByteSlice)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        tls_serialize_bytes #v_W writer self.Tls_codec.Quic_vec._0
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }
