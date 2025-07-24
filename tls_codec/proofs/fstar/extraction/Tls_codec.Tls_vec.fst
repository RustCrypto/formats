module Tls_codec.Tls_vec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Std.Io in
  let open Tls_codec in
  let open Tls_codec.Primitives in
  let open Zeroize in
  ()

type t_TlsVecU8 (v_T: Type0) = { f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> Core.Fmt.t_Debug (t_TlsVecU8 v_T)

unfold
let impl_18 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T) =
  impl_18' #v_T #i1

/// Create a new `TlsVec` from a Rust Vec.
let impl_7__new (#v_T: Type0) (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) : t_TlsVecU8 v_T =
  { f_vec = vec } <: t_TlsVecU8 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_TlsVecU8 v_T) =
  {
    f_clone_pre = (fun (self: t_TlsVecU8 v_T) -> true);
    f_clone_post = (fun (self: t_TlsVecU8 v_T) (out: t_TlsVecU8 v_T) -> true);
    f_clone
    =
    fun (self: t_TlsVecU8 v_T) ->
      impl_7__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_7__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_TlsVecU8 v_T = { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_TlsVecU8 v_T

/// Get the length of the vector.
let impl_7__len (#v_T: Type0) (self: t_TlsVecU8 v_T) : usize =
  Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_7__as_slice (#v_T: Type0) (self: t_TlsVecU8 v_T) : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_7__is_empty (#v_T: Type0) (self: t_TlsVecU8 v_T) : bool =
  Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_7__into_vec (#v_T: Type0) (self: t_TlsVecU8 v_T) : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsVecU8 v_T = { self with f_vec = tmp0 } <: t_TlsVecU8 v_T in
  out

/// Add an element to this.
let impl_7__push (#v_T: Type0) (self: t_TlsVecU8 v_T) (value: v_T) : t_TlsVecU8 v_T =
  let self:t_TlsVecU8 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsVecU8 v_T
  in
  self

/// Remove the last element.
let impl_7__pop (#v_T: Type0) (self: t_TlsVecU8 v_T) : (t_TlsVecU8 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsVecU8 v_T = { self with f_vec = tmp0 } <: t_TlsVecU8 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_TlsVecU8 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_7__remove (#v_T: Type0) (self: t_TlsVecU8 v_T) (index: usize) : (t_TlsVecU8 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsVecU8 v_T = { self with f_vec = tmp0 } <: t_TlsVecU8 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_TlsVecU8 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_7__get (#v_T: Type0) (self: t_TlsVecU8 v_T) (index: usize) : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_7__iter (#v_T: Type0) (self: t_TlsVecU8 v_T) : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_7__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_TlsVecU8 v_T)
      (f: v_F)
    : t_TlsVecU8 v_T =
  let self:t_TlsVecU8 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsVecU8 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_7__len_len (#v_T: Type0) (_: Prims.unit) : usize = mk_usize 1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_8 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_TlsVecU8 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU8 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU8 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
      (self: t_TlsVecU8 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_9 (#v_T: Type0) : Core.Ops.Index.t_Index (t_TlsVecU8 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_TlsVecU8 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsVecU8 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_TlsVecU8 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_10
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_TlsVecU8 v_T) (t_TlsVecU8 v_T) =
  {
    f_eq_pre = (fun (self: t_TlsVecU8 v_T) (other: t_TlsVecU8 v_T) -> true);
    f_eq_post = (fun (self: t_TlsVecU8 v_T) (other: t_TlsVecU8 v_T) (out: bool) -> true);
    f_eq = fun (self: t_TlsVecU8 v_T) (other: t_TlsVecU8 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> Core.Cmp.t_Eq (t_TlsVecU8 v_T)

unfold
let impl_17 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T) =
  impl_17' #v_T #i1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_11 (#v_T: Type0) : Core.Borrow.t_Borrow (t_TlsVecU8 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_TlsVecU8 v_T) -> true);
    f_borrow_post = (fun (self: t_TlsVecU8 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_TlsVecU8 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_12 (#v_T: Type0) : Core.Iter.Traits.Collect.t_FromIterator (t_TlsVecU8 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsVecU8 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsVecU8 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_13 (#v_T: Type0)
    : Core.Convert.t_From (t_TlsVecU8 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_TlsVecU8 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_7__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_14 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_TlsVecU8 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_TlsVecU8 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_7__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_15 (#v_T: Type0)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_TlsVecU8 v_T) =
  {
    f_from_pre = (fun (v: t_TlsVecU8 v_T) -> true);
    f_from_post = (fun (v: t_TlsVecU8 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsVecU8 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsVecU8 v_T = { v with f_vec = tmp0 } <: t_TlsVecU8 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_16 (#v_T: Type0) : Core.Default.t_Default (t_TlsVecU8 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsVecU8 v_T) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU8 v_T
  }

let impl_2__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU8 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_3__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsVecU8 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_7__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 1)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_20 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU8 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU8 v_T) -> impl_3__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_22 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU8 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU8 v_T) -> impl_3__tls_serialized_length #v_T self
  }

let impl_2__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU8 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsVecU8 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 1 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u8__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_2__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU8 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_2__get_content_lengths #v_T self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u8
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u8
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u8 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
          <:
          u8)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_7__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist118 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist118 <: (v_W & usize))
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
            match
              impl_2__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_19 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_2__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_21 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_2__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_4__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error) =
  let result:t_TlsVecU8 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU8 v_T in
  let tmp0, out:(v_R & Core.Result.t_Result u8 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u8 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU8 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU8 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU8 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_TlsVecU8 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU8 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU8 v_T = impl_7__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_TlsVecU8 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU8 v_T))) (v_R & usize & t_TlsVecU8 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_TlsVecU8 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU8 v_T))) (v_R & usize & t_TlsVecU8 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
          (v_R & usize & t_TlsVecU8 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result <: Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_23
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_TlsVecU8 v_T) =
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
        (out1: (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error) =
        impl_4__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU8 v_T) Tls_codec.t_Error)
  }

let impl_5__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_TlsVecU8 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU8 v_T in
  match
    Tls_codec.f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u8 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU8 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU8 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU8 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU8 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU8 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU8 v_T = impl_7__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU8 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU8 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU8 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_TlsVecU8 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU8 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU8 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_TlsVecU8 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_TlsVecU8 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_24
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_TlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_5__deserialize_bytes #v_T bytes
  }

type t_TlsVecU16 (v_T: Type0) = { f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_41': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> Core.Fmt.t_Debug (t_TlsVecU16 v_T)

unfold
let impl_41 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T) =
  impl_41' #v_T #i1

/// Create a new `TlsVec` from a Rust Vec.
let impl_30__new (#v_T: Type0) (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) : t_TlsVecU16 v_T =
  { f_vec = vec } <: t_TlsVecU16 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_29 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_TlsVecU16 v_T) =
  {
    f_clone_pre = (fun (self: t_TlsVecU16 v_T) -> true);
    f_clone_post = (fun (self: t_TlsVecU16 v_T) (out: t_TlsVecU16 v_T) -> true);
    f_clone
    =
    fun (self: t_TlsVecU16 v_T) ->
      impl_30__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_30__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_TlsVecU16 v_T = { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_TlsVecU16 v_T

/// Get the length of the vector.
let impl_30__len (#v_T: Type0) (self: t_TlsVecU16 v_T) : usize =
  Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_30__as_slice (#v_T: Type0) (self: t_TlsVecU16 v_T) : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_30__is_empty (#v_T: Type0) (self: t_TlsVecU16 v_T) : bool =
  Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_30__into_vec (#v_T: Type0) (self: t_TlsVecU16 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsVecU16 v_T = { self with f_vec = tmp0 } <: t_TlsVecU16 v_T in
  out

/// Add an element to this.
let impl_30__push (#v_T: Type0) (self: t_TlsVecU16 v_T) (value: v_T) : t_TlsVecU16 v_T =
  let self:t_TlsVecU16 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsVecU16 v_T
  in
  self

/// Remove the last element.
let impl_30__pop (#v_T: Type0) (self: t_TlsVecU16 v_T)
    : (t_TlsVecU16 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsVecU16 v_T = { self with f_vec = tmp0 } <: t_TlsVecU16 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_TlsVecU16 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_30__remove (#v_T: Type0) (self: t_TlsVecU16 v_T) (index: usize) : (t_TlsVecU16 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsVecU16 v_T = { self with f_vec = tmp0 } <: t_TlsVecU16 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_TlsVecU16 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_30__get (#v_T: Type0) (self: t_TlsVecU16 v_T) (index: usize) : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_30__iter (#v_T: Type0) (self: t_TlsVecU16 v_T) : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_30__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_TlsVecU16 v_T)
      (f: v_F)
    : t_TlsVecU16 v_T =
  let self:t_TlsVecU16 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsVecU16 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_30__len_len (#v_T: Type0) (_: Prims.unit) : usize = mk_usize 2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_31 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_TlsVecU16 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU16 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU16 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
      (self: t_TlsVecU16 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_32 (#v_T: Type0) : Core.Ops.Index.t_Index (t_TlsVecU16 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_TlsVecU16 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsVecU16 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_TlsVecU16 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_33
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_TlsVecU16 v_T) (t_TlsVecU16 v_T) =
  {
    f_eq_pre = (fun (self: t_TlsVecU16 v_T) (other: t_TlsVecU16 v_T) -> true);
    f_eq_post = (fun (self: t_TlsVecU16 v_T) (other: t_TlsVecU16 v_T) (out: bool) -> true);
    f_eq = fun (self: t_TlsVecU16 v_T) (other: t_TlsVecU16 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_40': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> Core.Cmp.t_Eq (t_TlsVecU16 v_T)

unfold
let impl_40 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T) =
  impl_40' #v_T #i1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_34 (#v_T: Type0) : Core.Borrow.t_Borrow (t_TlsVecU16 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_TlsVecU16 v_T) -> true);
    f_borrow_post = (fun (self: t_TlsVecU16 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_TlsVecU16 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_35 (#v_T: Type0) : Core.Iter.Traits.Collect.t_FromIterator (t_TlsVecU16 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsVecU16 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsVecU16 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_36 (#v_T: Type0)
    : Core.Convert.t_From (t_TlsVecU16 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_TlsVecU16 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_30__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_37 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_TlsVecU16 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_TlsVecU16 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_30__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_38 (#v_T: Type0)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_TlsVecU16 v_T) =
  {
    f_from_pre = (fun (v: t_TlsVecU16 v_T) -> true);
    f_from_post
    =
    (fun (v: t_TlsVecU16 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsVecU16 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsVecU16 v_T = { v with f_vec = tmp0 } <: t_TlsVecU16 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_39 (#v_T: Type0) : Core.Default.t_Default (t_TlsVecU16 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsVecU16 v_T) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU16 v_T
  }

let impl_25__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU16 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_26__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsVecU16 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_30__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 2)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_43 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU16 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU16 v_T) -> impl_26__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_45 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU16 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU16 v_T) -> impl_26__tls_serialized_length #v_T self
  }

let impl_25__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU16 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsVecU16 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 2 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u16__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_25__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU16 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_25__get_content_lengths #v_T self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u16
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u16
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u16 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
          <:
          u16)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_30__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist126 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist126 <: (v_W & usize))
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
            match
              impl_25__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_42 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_25__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_44 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_25__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_27__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error) =
  let result:t_TlsVecU16 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU16 v_T in
  let tmp0, out:(v_R & Core.Result.t_Result u16 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u16 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u16 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU16 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU16 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU16 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_TlsVecU16 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU16 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU16 v_T = impl_30__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_TlsVecU16 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU16 v_T)))
                  (v_R & usize & t_TlsVecU16 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_TlsVecU16 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU16 v_T)))
                  (v_R & usize & t_TlsVecU16 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
          (v_R & usize & t_TlsVecU16 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result <: Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_46
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_TlsVecU16 v_T) =
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
        (out1: (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error) =
        impl_27__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU16 v_T) Tls_codec.t_Error)
  }

let impl_28__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_TlsVecU16 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU16 v_T in
  match
    Tls_codec.f_tls_deserialize_bytes #u16 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u16 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU16 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU16 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU16 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU16 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU16 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU16 v_T = impl_30__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU16 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU16 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU16 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_TlsVecU16 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU16 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU16 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_TlsVecU16 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_TlsVecU16 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_47
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_TlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_28__deserialize_bytes #v_T bytes
  }

type t_TlsVecU24 (v_T: Type0) = { f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_64': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> Core.Fmt.t_Debug (t_TlsVecU24 v_T)

unfold
let impl_64 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T) =
  impl_64' #v_T #i1

/// Create a new `TlsVec` from a Rust Vec.
let impl_53__new (#v_T: Type0) (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) : t_TlsVecU24 v_T =
  { f_vec = vec } <: t_TlsVecU24 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_52 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_TlsVecU24 v_T) =
  {
    f_clone_pre = (fun (self: t_TlsVecU24 v_T) -> true);
    f_clone_post = (fun (self: t_TlsVecU24 v_T) (out: t_TlsVecU24 v_T) -> true);
    f_clone
    =
    fun (self: t_TlsVecU24 v_T) ->
      impl_53__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_53__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_TlsVecU24 v_T = { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_TlsVecU24 v_T

/// Get the length of the vector.
let impl_53__len (#v_T: Type0) (self: t_TlsVecU24 v_T) : usize =
  Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_53__as_slice (#v_T: Type0) (self: t_TlsVecU24 v_T) : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_53__is_empty (#v_T: Type0) (self: t_TlsVecU24 v_T) : bool =
  Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_53__into_vec (#v_T: Type0) (self: t_TlsVecU24 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsVecU24 v_T = { self with f_vec = tmp0 } <: t_TlsVecU24 v_T in
  out

/// Add an element to this.
let impl_53__push (#v_T: Type0) (self: t_TlsVecU24 v_T) (value: v_T) : t_TlsVecU24 v_T =
  let self:t_TlsVecU24 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsVecU24 v_T
  in
  self

/// Remove the last element.
let impl_53__pop (#v_T: Type0) (self: t_TlsVecU24 v_T)
    : (t_TlsVecU24 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsVecU24 v_T = { self with f_vec = tmp0 } <: t_TlsVecU24 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_TlsVecU24 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_53__remove (#v_T: Type0) (self: t_TlsVecU24 v_T) (index: usize) : (t_TlsVecU24 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsVecU24 v_T = { self with f_vec = tmp0 } <: t_TlsVecU24 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_TlsVecU24 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_53__get (#v_T: Type0) (self: t_TlsVecU24 v_T) (index: usize) : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_53__iter (#v_T: Type0) (self: t_TlsVecU24 v_T) : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_53__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_TlsVecU24 v_T)
      (f: v_F)
    : t_TlsVecU24 v_T =
  let self:t_TlsVecU24 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsVecU24 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_53__len_len (#v_T: Type0) (_: Prims.unit) : usize = mk_usize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_54 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_TlsVecU24 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU24 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU24 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
      (self: t_TlsVecU24 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_55 (#v_T: Type0) : Core.Ops.Index.t_Index (t_TlsVecU24 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_TlsVecU24 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsVecU24 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_TlsVecU24 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_56
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_TlsVecU24 v_T) (t_TlsVecU24 v_T) =
  {
    f_eq_pre = (fun (self: t_TlsVecU24 v_T) (other: t_TlsVecU24 v_T) -> true);
    f_eq_post = (fun (self: t_TlsVecU24 v_T) (other: t_TlsVecU24 v_T) (out: bool) -> true);
    f_eq = fun (self: t_TlsVecU24 v_T) (other: t_TlsVecU24 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_63': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> Core.Cmp.t_Eq (t_TlsVecU24 v_T)

unfold
let impl_63 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T) =
  impl_63' #v_T #i1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_57 (#v_T: Type0) : Core.Borrow.t_Borrow (t_TlsVecU24 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_TlsVecU24 v_T) -> true);
    f_borrow_post = (fun (self: t_TlsVecU24 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_TlsVecU24 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_58 (#v_T: Type0) : Core.Iter.Traits.Collect.t_FromIterator (t_TlsVecU24 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsVecU24 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsVecU24 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_59 (#v_T: Type0)
    : Core.Convert.t_From (t_TlsVecU24 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_TlsVecU24 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_53__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_60 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_TlsVecU24 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_TlsVecU24 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_53__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_61 (#v_T: Type0)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_TlsVecU24 v_T) =
  {
    f_from_pre = (fun (v: t_TlsVecU24 v_T) -> true);
    f_from_post
    =
    (fun (v: t_TlsVecU24 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsVecU24 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsVecU24 v_T = { v with f_vec = tmp0 } <: t_TlsVecU24 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_62 (#v_T: Type0) : Core.Default.t_Default (t_TlsVecU24 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsVecU24 v_T) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU24 v_T
  }

let impl_48__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU24 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_49__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsVecU24 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_53__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 3)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_66 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU24 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU24 v_T) -> impl_49__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_68 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU24 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU24 v_T) -> impl_49__tls_serialized_length #v_T self
  }

let impl_48__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU24 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsVecU24 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 3 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #Tls_codec.t_U24
          #usize
          #FStar.Tactics.Typeclasses.solve
          Tls_codec.impl_U24__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_48__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU24 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_48__get_content_lengths #v_T self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #Tls_codec.t_U24
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #Tls_codec.t_U24
            #Tls_codec.t_Error
            (Core.Convert.f_try_from #Tls_codec.t_U24
                #usize
                #FStar.Tactics.Typeclasses.solve
                byte_length
              <:
              Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
          <:
          Tls_codec.t_U24)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_53__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist134 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist134 <: (v_W & usize))
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
            match
              impl_48__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_65 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_48__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_67 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_48__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_50__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error) =
  let result:t_TlsVecU24 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU24 v_T in
  let tmp0, out:(v_R & Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize =
      Tls_codec.f_tls_serialized_len #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve len
    in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU24 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #Tls_codec.t_U24
                      #usize
                      #FStar.Tactics.Typeclasses.solve
                      len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU24 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU24 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_TlsVecU24 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU24 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU24 v_T = impl_53__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_TlsVecU24 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU24 v_T)))
                  (v_R & usize & t_TlsVecU24 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_TlsVecU24 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU24 v_T)))
                  (v_R & usize & t_TlsVecU24 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
          (v_R & usize & t_TlsVecU24 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result <: Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_69
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_TlsVecU24 v_T) =
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
        (out1: (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error) =
        impl_50__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU24 v_T) Tls_codec.t_Error)
  }

let impl_51__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_TlsVecU24 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU24 v_T in
  match
    Tls_codec.f_tls_deserialize_bytes #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (Tls_codec.t_U24 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize =
      Tls_codec.f_tls_serialized_len #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve len
    in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU24 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #Tls_codec.t_U24
                      #usize
                      #FStar.Tactics.Typeclasses.solve
                      len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU24 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU24 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU24 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU24 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU24 v_T = impl_53__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU24 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU24 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU24 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_TlsVecU24 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU24 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU24 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_TlsVecU24 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_TlsVecU24 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_70
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_TlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_51__deserialize_bytes #v_T bytes
  }

type t_TlsVecU32 (v_T: Type0) = { f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_87': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> Core.Fmt.t_Debug (t_TlsVecU32 v_T)

unfold
let impl_87 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T) =
  impl_87' #v_T #i1

/// Create a new `TlsVec` from a Rust Vec.
let impl_76__new (#v_T: Type0) (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) : t_TlsVecU32 v_T =
  { f_vec = vec } <: t_TlsVecU32 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_75 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_TlsVecU32 v_T) =
  {
    f_clone_pre = (fun (self: t_TlsVecU32 v_T) -> true);
    f_clone_post = (fun (self: t_TlsVecU32 v_T) (out: t_TlsVecU32 v_T) -> true);
    f_clone
    =
    fun (self: t_TlsVecU32 v_T) ->
      impl_76__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_76__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_TlsVecU32 v_T = { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_TlsVecU32 v_T

/// Get the length of the vector.
let impl_76__len (#v_T: Type0) (self: t_TlsVecU32 v_T) : usize =
  Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_76__as_slice (#v_T: Type0) (self: t_TlsVecU32 v_T) : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_76__is_empty (#v_T: Type0) (self: t_TlsVecU32 v_T) : bool =
  Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_76__into_vec (#v_T: Type0) (self: t_TlsVecU32 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsVecU32 v_T = { self with f_vec = tmp0 } <: t_TlsVecU32 v_T in
  out

/// Add an element to this.
let impl_76__push (#v_T: Type0) (self: t_TlsVecU32 v_T) (value: v_T) : t_TlsVecU32 v_T =
  let self:t_TlsVecU32 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsVecU32 v_T
  in
  self

/// Remove the last element.
let impl_76__pop (#v_T: Type0) (self: t_TlsVecU32 v_T)
    : (t_TlsVecU32 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsVecU32 v_T = { self with f_vec = tmp0 } <: t_TlsVecU32 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_TlsVecU32 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_76__remove (#v_T: Type0) (self: t_TlsVecU32 v_T) (index: usize) : (t_TlsVecU32 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsVecU32 v_T = { self with f_vec = tmp0 } <: t_TlsVecU32 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_TlsVecU32 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_76__get (#v_T: Type0) (self: t_TlsVecU32 v_T) (index: usize) : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_76__iter (#v_T: Type0) (self: t_TlsVecU32 v_T) : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_76__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_TlsVecU32 v_T)
      (f: v_F)
    : t_TlsVecU32 v_T =
  let self:t_TlsVecU32 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsVecU32 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_76__len_len (#v_T: Type0) (_: Prims.unit) : usize = mk_usize 4

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_77 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_TlsVecU32 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU32 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
        (self: t_TlsVecU32 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Hash.t_Hasher v_H)
      (self: t_TlsVecU32 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_78 (#v_T: Type0) : Core.Ops.Index.t_Index (t_TlsVecU32 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_TlsVecU32 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsVecU32 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_TlsVecU32 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_79
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_TlsVecU32 v_T) (t_TlsVecU32 v_T) =
  {
    f_eq_pre = (fun (self: t_TlsVecU32 v_T) (other: t_TlsVecU32 v_T) -> true);
    f_eq_post = (fun (self: t_TlsVecU32 v_T) (other: t_TlsVecU32 v_T) (out: bool) -> true);
    f_eq = fun (self: t_TlsVecU32 v_T) (other: t_TlsVecU32 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_86': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> Core.Cmp.t_Eq (t_TlsVecU32 v_T)

unfold
let impl_86 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T) =
  impl_86' #v_T #i1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_80 (#v_T: Type0) : Core.Borrow.t_Borrow (t_TlsVecU32 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_TlsVecU32 v_T) -> true);
    f_borrow_post = (fun (self: t_TlsVecU32 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_TlsVecU32 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_81 (#v_T: Type0) : Core.Iter.Traits.Collect.t_FromIterator (t_TlsVecU32 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsVecU32 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsVecU32 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_82 (#v_T: Type0)
    : Core.Convert.t_From (t_TlsVecU32 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_TlsVecU32 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_76__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_83 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_TlsVecU32 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_TlsVecU32 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_76__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_84 (#v_T: Type0)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_TlsVecU32 v_T) =
  {
    f_from_pre = (fun (v: t_TlsVecU32 v_T) -> true);
    f_from_post
    =
    (fun (v: t_TlsVecU32 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsVecU32 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsVecU32 v_T = { v with f_vec = tmp0 } <: t_TlsVecU32 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_85 (#v_T: Type0) : Core.Default.t_Default (t_TlsVecU32 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsVecU32 v_T) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU32 v_T
  }

let impl_71__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU32 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_72__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsVecU32 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_76__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 4)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_89 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU32 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU32 v_T) -> impl_72__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_91 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsVecU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsVecU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsVecU32 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsVecU32 v_T) -> impl_72__tls_serialized_length #v_T self
  }

let impl_71__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsVecU32 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsVecU32 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 4 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Num.Error.t_TryFromIntError
      (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u32__MAX
        <:
        Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_71__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU32 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_71__get_content_lengths #v_T self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u32
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u32
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u32 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
          <:
          u32)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_76__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist142 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist142 <: (v_W & usize))
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
            match
              impl_71__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_88 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_71__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_90 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsVecU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsVecU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_71__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_73__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error) =
  let result:t_TlsVecU32 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU32 v_T in
  let tmp0, out:(v_R & Core.Result.t_Result u32 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u32 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u32 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u32 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU32 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Num.Error.t_TryFromIntError
                  (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU32 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU32 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_TlsVecU32 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_TlsVecU32 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU32 v_T = impl_76__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_TlsVecU32 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU32 v_T)))
                  (v_R & usize & t_TlsVecU32 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_TlsVecU32 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_TlsVecU32 v_T)))
                  (v_R & usize & t_TlsVecU32 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
          (v_R & usize & t_TlsVecU32 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result <: Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_92
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_TlsVecU32 v_T) =
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
        (out1: (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error) =
        impl_73__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result (t_TlsVecU32 v_T) Tls_codec.t_Error)
  }

let impl_74__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_TlsVecU32 v_T = { f_vec = Alloc.Vec.impl__new #v_T () } <: t_TlsVecU32 v_T in
  match
    Tls_codec.f_tls_deserialize_bytes #u32 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u32 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u32 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU32 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Num.Error.t_TryFromIntError
                  (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU32 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU32 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU32 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_TlsVecU32 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_TlsVecU32 v_T = impl_76__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_TlsVecU32 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU32 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU32 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_TlsVecU32 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_TlsVecU32 v_T)))
                  (usize & t_Slice u8 & t_TlsVecU32 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_TlsVecU32 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_TlsVecU32 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_93
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_TlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_74__deserialize_bytes #v_T bytes
  }

type t_TlsByteVecU8 = { f_vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl_106: Core.Clone.t_Clone t_TlsByteVecU8 = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_107': Core.Fmt.t_Debug t_TlsByteVecU8

unfold
let impl_107 = impl_107'

/// Create a new `TlsVec` from a Rust Vec.
let impl_TlsByteVecU8__new (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_TlsByteVecU8 =
  { f_vec = vec } <: t_TlsByteVecU8

/// Create a new `TlsVec` from a slice.
let impl_TlsByteVecU8__from_slice
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Core.Clone.t_Clone u8)
      (slice: t_Slice u8)
    : t_TlsByteVecU8 = { f_vec = Alloc.Slice.impl__to_vec #u8 slice } <: t_TlsByteVecU8

/// Get the length of the vector.
let impl_TlsByteVecU8__len (self: t_TlsByteVecU8) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_TlsByteVecU8__as_slice (self: t_TlsByteVecU8) : t_Slice u8 =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_TlsByteVecU8__is_empty (self: t_TlsByteVecU8) : bool =
  Alloc.Vec.impl_1__is_empty #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_TlsByteVecU8__into_vec (self: t_TlsByteVecU8) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsByteVecU8 = { self with f_vec = tmp0 } <: t_TlsByteVecU8 in
  out

/// Add an element to this.
let impl_TlsByteVecU8__push (self: t_TlsByteVecU8) (value: u8) : t_TlsByteVecU8 =
  let self:t_TlsByteVecU8 =
    { self with f_vec = Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsByteVecU8
  in
  self

/// Remove the last element.
let impl_TlsByteVecU8__pop (self: t_TlsByteVecU8) : (t_TlsByteVecU8 & Core.Option.t_Option u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Core.Option.t_Option u8) =
    Alloc.Vec.impl_1__pop #u8 #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsByteVecU8 = { self with f_vec = tmp0 } <: t_TlsByteVecU8 in
  let hax_temp_output:Core.Option.t_Option u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU8 & Core.Option.t_Option u8)

/// Remove the element at `index`.
let impl_TlsByteVecU8__remove (self: t_TlsByteVecU8) (index: usize) : (t_TlsByteVecU8 & u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & u8) =
    Alloc.Vec.impl_1__remove #u8 #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsByteVecU8 = { self with f_vec = tmp0 } <: t_TlsByteVecU8 in
  let hax_temp_output:u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU8 & u8)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_TlsByteVecU8__get (self: t_TlsByteVecU8) (index: usize) : Core.Option.t_Option u8 =
  Core.Slice.impl__get #u8
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)
    index

/// Returns an iterator over the slice.
let impl_TlsByteVecU8__iter (self: t_TlsByteVecU8) : Core.Slice.Iter.t_Iter u8 =
  Core.Slice.impl__iter #u8
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)

/// Retains only the elements specified by the predicate.
let impl_TlsByteVecU8__retain
      (#v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Ops.Function.t_FnMut v_F u8)
      (self: t_TlsByteVecU8)
      (f: v_F)
    : t_TlsByteVecU8 =
  let self:t_TlsByteVecU8 =
    { self with f_vec = Alloc.Vec.impl_1__retain #u8 #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsByteVecU8
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_TlsByteVecU8__len_len (_: Prims.unit) : usize = mk_usize 1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_96: Core.Hash.t_Hash t_TlsByteVecU8 =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU8)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU8)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
      (self: t_TlsByteVecU8)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_97: Core.Ops.Index.t_Index t_TlsByteVecU8 usize =
  {
    f_Output = u8;
    f_index_pre = (fun (self: t_TlsByteVecU8) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsByteVecU8) (i: usize) (out: u8) -> true);
    f_index = fun (self: t_TlsByteVecU8) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_98: Core.Cmp.t_PartialEq t_TlsByteVecU8 t_TlsByteVecU8 =
  {
    f_eq_pre = (fun (self: t_TlsByteVecU8) (other: t_TlsByteVecU8) -> true);
    f_eq_post = (fun (self: t_TlsByteVecU8) (other: t_TlsByteVecU8) (out: bool) -> true);
    f_eq = fun (self: t_TlsByteVecU8) (other: t_TlsByteVecU8) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_105': Core.Cmp.t_Eq t_TlsByteVecU8

unfold
let impl_105 = impl_105'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_99: Core.Borrow.t_Borrow t_TlsByteVecU8 (t_Slice u8) =
  {
    f_borrow_pre = (fun (self: t_TlsByteVecU8) -> true);
    f_borrow_post = (fun (self: t_TlsByteVecU8) (out: t_Slice u8) -> true);
    f_borrow
    =
    fun (self: t_TlsByteVecU8) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_100: Core.Iter.Traits.Collect.t_FromIterator t_TlsByteVecU8 u8 =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsByteVecU8)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #u8
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsByteVecU8
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_101: Core.Convert.t_From t_TlsByteVecU8 (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_TlsByteVecU8) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_TlsByteVecU8__new v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_102: Core.Convert.t_From t_TlsByteVecU8 (t_Slice u8) =
  {
    f_from_pre = (fun (v: t_Slice u8) -> true);
    f_from_post = (fun (v: t_Slice u8) (out: t_TlsByteVecU8) -> true);
    f_from = fun (v: t_Slice u8) -> impl_TlsByteVecU8__from_slice v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_103: Core.Convert.t_From (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_TlsByteVecU8 =
  {
    f_from_pre = (fun (v: t_TlsByteVecU8) -> true);
    f_from_post = (fun (v: t_TlsByteVecU8) (out1: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsByteVecU8) ->
      let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsByteVecU8 = { v with f_vec = tmp0 } <: t_TlsByteVecU8 in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_104: Core.Default.t_Default t_TlsByteVecU8 =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsByteVecU8) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #u8 () } <: t_TlsByteVecU8
  }

let impl_TlsByteVecU8__assert_written_bytes
      (self: t_TlsByteVecU8)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_TlsByteVecU8__tls_serialized_byte_length (self: t_TlsByteVecU8) : usize =
  (Core.Slice.impl__len #u8 (impl_TlsByteVecU8__as_slice self <: t_Slice u8) <: usize) +! mk_usize 1

let impl_TlsByteVecU8__deserialize_bytes
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error) =
  let tmp0, out:(v_R & Core.Result.t_Result u8 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u8 Tls_codec.t_Error with
  | Core.Result.Result_Ok hoist153 ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve hoist153
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
    then
      bytes,
      (Core.Result.Result_Err
        (Tls_codec.Error_DecodingError
          (Core.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                      (mk_usize 2)
                      (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                        Rust_primitives.Hax.array_of_list 3 list)
                      (let list =
                          [
                            Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                            Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
        Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
      <:
      (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
    else
      let result:t_TlsByteVecU8 =
        { f_vec = Alloc.Vec.from_elem #u8 (mk_u8 0) len } <: t_TlsByteVecU8
      in
      let tmp0, tmp1, out:(v_R & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes result.f_vec
      in
      let bytes:v_R = tmp0 in
      let result:t_TlsByteVecU8 = { result with f_vec = tmp1 } <: t_TlsByteVecU8 in
      (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          let hax_temp_output:Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error =
            Core.Result.Result_Ok result <: Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error
          in
          bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          bytes,
          (Core.Result.Result_Err
            (Core.Convert.f_from #Tls_codec.t_Error
                #Std.Io.Error.t_Error
                #FStar.Tactics.Typeclasses.solve
                err)
            <:
            Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)

let impl_TlsByteVecU8__deserialize_bytes_bytes (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error =
  match
    Tls_codec.f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u8 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (type_len, remainder) ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve type_len
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
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
                          Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
      Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error
    else
      (match
          Core.Option.impl__ok_or #(t_Slice u8)
            #Tls_codec.t_Error
            (Core.Slice.impl__get #u8
                #(Core.Ops.Range.t_Range usize)
                bytes
                ({
                    Core.Ops.Range.f_start = mk_usize 1;
                    Core.Ops.Range.f_end = len +! mk_usize 1 <: usize
                  }
                  <:
                  Core.Ops.Range.t_Range usize)
              <:
              Core.Option.t_Option (t_Slice u8))
            (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
          <:
          Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
        with
        | Core.Result.Result_Ok vec ->
          let result:t_TlsByteVecU8 =
            { f_vec = Alloc.Slice.impl__to_vec #u8 vec } <: t_TlsByteVecU8
          in
          (match
              Core.Option.impl__ok_or #(t_Slice u8)
                #Tls_codec.t_Error
                (Core.Slice.impl__get #u8
                    #(Core.Ops.Range.t_RangeFrom usize)
                    remainder
                    ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                  <:
                  Core.Option.t_Option (t_Slice u8))
                (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
            with
            | Core.Result.Result_Ok hoist158 ->
              Core.Result.Result_Ok (result, hoist158 <: (t_TlsByteVecU8 & t_Slice u8))
              <:
              Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error
            | Core.Result.Result_Err err ->
              Core.Result.Result_Err err
              <:
              Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          Core.Result.Result_Err err
          <:
          Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_109: Tls_codec.t_Size t_TlsByteVecU8 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU8) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU8) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU8) -> impl_TlsByteVecU8__tls_serialized_byte_length self
  }

let impl_TlsByteVecU8__get_content_lengths (self: t_TlsByteVecU8)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteVecU8 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 1 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u8__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_TlsByteVecU8__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU8)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_TlsByteVecU8__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u8
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u8
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u8 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
          <:
          u8)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_TlsByteVecU8__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist150 ->
            let written:usize = written +! hoist150 in
            (match
                impl_TlsByteVecU8__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

let impl_TlsByteVecU8__serialize_bytes_bytes (self: t_TlsByteVecU8)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error =
  match
    impl_TlsByteVecU8__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #u8 tls_serialized_len
    in
    (match
        Tls_codec.f_tls_serialize_bytes #u8
          #FStar.Tactics.Typeclasses.solve
          (Core.Result.impl__unwrap #u8
              #Core.Num.Error.t_TryFromIntError
              (Core.Convert.f_try_into #usize #u8 #FStar.Tactics.Typeclasses.solve byte_length
                <:
                Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
            <:
            u8)
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok length_vec ->
        let written:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_vec in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8
            #Alloc.Alloc.t_Global
            vec
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                length_vec
              <:
              t_Slice u8)
        in
        let bytes:t_Slice u8 = impl_TlsByteVecU8__as_slice self in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global vec bytes
        in
        let written:usize = written +! (Core.Slice.impl__len #u8 bytes <: usize) in
        (match
            impl_TlsByteVecU8__assert_written_bytes self tls_serialized_len written
            <:
            Core.Result.t_Result Prims.unit Tls_codec.t_Error
          with
          | Core.Result.Result_Ok _ ->
            Core.Result.Result_Ok vec
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_108: Tls_codec.t_Serialize t_TlsByteVecU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU8__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_111: Tls_codec.t_Size t_TlsByteVecU8 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU8) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU8) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU8) -> impl_TlsByteVecU8__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_110: Tls_codec.t_Serialize t_TlsByteVecU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU8__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_112: Tls_codec.t_Deserialize t_TlsByteVecU8 =
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
        (out1: (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error) =
        impl_TlsByteVecU8__deserialize_bytes #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU8 Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_113: Tls_codec.t_DeserializeBytes t_TlsByteVecU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsByteVecU8 & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) -> impl_TlsByteVecU8__deserialize_bytes_bytes bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_114: Tls_codec.t_SerializeBytes t_TlsByteVecU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_TlsByteVecU8) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_TlsByteVecU8)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_TlsByteVecU8) -> impl_TlsByteVecU8__serialize_bytes_bytes self
  }

type t_TlsByteVecU16 = { f_vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl_127: Core.Clone.t_Clone t_TlsByteVecU16 = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_128': Core.Fmt.t_Debug t_TlsByteVecU16

unfold
let impl_128 = impl_128'

/// Create a new `TlsVec` from a Rust Vec.
let impl_TlsByteVecU16__new (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_TlsByteVecU16 =
  { f_vec = vec } <: t_TlsByteVecU16

/// Create a new `TlsVec` from a slice.
let impl_TlsByteVecU16__from_slice
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Core.Clone.t_Clone u8)
      (slice: t_Slice u8)
    : t_TlsByteVecU16 = { f_vec = Alloc.Slice.impl__to_vec #u8 slice } <: t_TlsByteVecU16

/// Get the length of the vector.
let impl_TlsByteVecU16__len (self: t_TlsByteVecU16) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_TlsByteVecU16__as_slice (self: t_TlsByteVecU16) : t_Slice u8 =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_TlsByteVecU16__is_empty (self: t_TlsByteVecU16) : bool =
  Alloc.Vec.impl_1__is_empty #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_TlsByteVecU16__into_vec (self: t_TlsByteVecU16) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsByteVecU16 = { self with f_vec = tmp0 } <: t_TlsByteVecU16 in
  out

/// Add an element to this.
let impl_TlsByteVecU16__push (self: t_TlsByteVecU16) (value: u8) : t_TlsByteVecU16 =
  let self:t_TlsByteVecU16 =
    { self with f_vec = Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsByteVecU16
  in
  self

/// Remove the last element.
let impl_TlsByteVecU16__pop (self: t_TlsByteVecU16) : (t_TlsByteVecU16 & Core.Option.t_Option u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Core.Option.t_Option u8) =
    Alloc.Vec.impl_1__pop #u8 #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsByteVecU16 = { self with f_vec = tmp0 } <: t_TlsByteVecU16 in
  let hax_temp_output:Core.Option.t_Option u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU16 & Core.Option.t_Option u8)

/// Remove the element at `index`.
let impl_TlsByteVecU16__remove (self: t_TlsByteVecU16) (index: usize) : (t_TlsByteVecU16 & u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & u8) =
    Alloc.Vec.impl_1__remove #u8 #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsByteVecU16 = { self with f_vec = tmp0 } <: t_TlsByteVecU16 in
  let hax_temp_output:u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU16 & u8)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_TlsByteVecU16__get (self: t_TlsByteVecU16) (index: usize) : Core.Option.t_Option u8 =
  Core.Slice.impl__get #u8
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)
    index

/// Returns an iterator over the slice.
let impl_TlsByteVecU16__iter (self: t_TlsByteVecU16) : Core.Slice.Iter.t_Iter u8 =
  Core.Slice.impl__iter #u8
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)

/// Retains only the elements specified by the predicate.
let impl_TlsByteVecU16__retain
      (#v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Ops.Function.t_FnMut v_F u8)
      (self: t_TlsByteVecU16)
      (f: v_F)
    : t_TlsByteVecU16 =
  let self:t_TlsByteVecU16 =
    { self with f_vec = Alloc.Vec.impl_1__retain #u8 #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsByteVecU16
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_TlsByteVecU16__len_len (_: Prims.unit) : usize = mk_usize 2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_117: Core.Hash.t_Hash t_TlsByteVecU16 =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU16)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU16)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
      (self: t_TlsByteVecU16)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_118: Core.Ops.Index.t_Index t_TlsByteVecU16 usize =
  {
    f_Output = u8;
    f_index_pre = (fun (self: t_TlsByteVecU16) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsByteVecU16) (i: usize) (out: u8) -> true);
    f_index = fun (self: t_TlsByteVecU16) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_119: Core.Cmp.t_PartialEq t_TlsByteVecU16 t_TlsByteVecU16 =
  {
    f_eq_pre = (fun (self: t_TlsByteVecU16) (other: t_TlsByteVecU16) -> true);
    f_eq_post = (fun (self: t_TlsByteVecU16) (other: t_TlsByteVecU16) (out: bool) -> true);
    f_eq = fun (self: t_TlsByteVecU16) (other: t_TlsByteVecU16) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_126': Core.Cmp.t_Eq t_TlsByteVecU16

unfold
let impl_126 = impl_126'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_120: Core.Borrow.t_Borrow t_TlsByteVecU16 (t_Slice u8) =
  {
    f_borrow_pre = (fun (self: t_TlsByteVecU16) -> true);
    f_borrow_post = (fun (self: t_TlsByteVecU16) (out: t_Slice u8) -> true);
    f_borrow
    =
    fun (self: t_TlsByteVecU16) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_121: Core.Iter.Traits.Collect.t_FromIterator t_TlsByteVecU16 u8 =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsByteVecU16)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #u8
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsByteVecU16
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_122: Core.Convert.t_From t_TlsByteVecU16 (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_TlsByteVecU16) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_TlsByteVecU16__new v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_123: Core.Convert.t_From t_TlsByteVecU16 (t_Slice u8) =
  {
    f_from_pre = (fun (v: t_Slice u8) -> true);
    f_from_post = (fun (v: t_Slice u8) (out: t_TlsByteVecU16) -> true);
    f_from = fun (v: t_Slice u8) -> impl_TlsByteVecU16__from_slice v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_124: Core.Convert.t_From (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_TlsByteVecU16 =
  {
    f_from_pre = (fun (v: t_TlsByteVecU16) -> true);
    f_from_post = (fun (v: t_TlsByteVecU16) (out1: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsByteVecU16) ->
      let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsByteVecU16 = { v with f_vec = tmp0 } <: t_TlsByteVecU16 in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_125: Core.Default.t_Default t_TlsByteVecU16 =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsByteVecU16) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #u8 () } <: t_TlsByteVecU16
  }

let impl_TlsByteVecU16__assert_written_bytes
      (self: t_TlsByteVecU16)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_TlsByteVecU16__tls_serialized_byte_length (self: t_TlsByteVecU16) : usize =
  (Core.Slice.impl__len #u8 (impl_TlsByteVecU16__as_slice self <: t_Slice u8) <: usize) +!
  mk_usize 2

let impl_TlsByteVecU16__deserialize_bytes
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error) =
  let tmp0, out:(v_R & Core.Result.t_Result u16 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u16 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u16 Tls_codec.t_Error with
  | Core.Result.Result_Ok hoist167 ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve hoist167
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
    then
      bytes,
      (Core.Result.Result_Err
        (Tls_codec.Error_DecodingError
          (Core.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                      (mk_usize 2)
                      (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                        Rust_primitives.Hax.array_of_list 3 list)
                      (let list =
                          [
                            Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                            Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
        Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
      <:
      (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
    else
      let result:t_TlsByteVecU16 =
        { f_vec = Alloc.Vec.from_elem #u8 (mk_u8 0) len } <: t_TlsByteVecU16
      in
      let tmp0, tmp1, out:(v_R & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes result.f_vec
      in
      let bytes:v_R = tmp0 in
      let result:t_TlsByteVecU16 = { result with f_vec = tmp1 } <: t_TlsByteVecU16 in
      (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          let hax_temp_output:Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error =
            Core.Result.Result_Ok result <: Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error
          in
          bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          bytes,
          (Core.Result.Result_Err
            (Core.Convert.f_from #Tls_codec.t_Error
                #Std.Io.Error.t_Error
                #FStar.Tactics.Typeclasses.solve
                err)
            <:
            Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)

let impl_TlsByteVecU16__deserialize_bytes_bytes (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error =
  match
    Tls_codec.f_tls_deserialize_bytes #u16 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u16 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (type_len, remainder) ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve type_len
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
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
                          Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
      Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error
    else
      (match
          Core.Option.impl__ok_or #(t_Slice u8)
            #Tls_codec.t_Error
            (Core.Slice.impl__get #u8
                #(Core.Ops.Range.t_Range usize)
                bytes
                ({
                    Core.Ops.Range.f_start = mk_usize 2;
                    Core.Ops.Range.f_end = len +! mk_usize 2 <: usize
                  }
                  <:
                  Core.Ops.Range.t_Range usize)
              <:
              Core.Option.t_Option (t_Slice u8))
            (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
          <:
          Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
        with
        | Core.Result.Result_Ok vec ->
          let result:t_TlsByteVecU16 =
            { f_vec = Alloc.Slice.impl__to_vec #u8 vec } <: t_TlsByteVecU16
          in
          (match
              Core.Option.impl__ok_or #(t_Slice u8)
                #Tls_codec.t_Error
                (Core.Slice.impl__get #u8
                    #(Core.Ops.Range.t_RangeFrom usize)
                    remainder
                    ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                  <:
                  Core.Option.t_Option (t_Slice u8))
                (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
            with
            | Core.Result.Result_Ok hoist172 ->
              Core.Result.Result_Ok (result, hoist172 <: (t_TlsByteVecU16 & t_Slice u8))
              <:
              Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error
            | Core.Result.Result_Err err ->
              Core.Result.Result_Err err
              <:
              Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          Core.Result.Result_Err err
          <:
          Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_130: Tls_codec.t_Size t_TlsByteVecU16 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU16) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU16) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU16) -> impl_TlsByteVecU16__tls_serialized_byte_length self
  }

let impl_TlsByteVecU16__get_content_lengths (self: t_TlsByteVecU16)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteVecU16 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 2 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u16__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_TlsByteVecU16__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU16)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_TlsByteVecU16__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u16
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u16
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u16 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
          <:
          u16)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_TlsByteVecU16__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist164 ->
            let written:usize = written +! hoist164 in
            (match
                impl_TlsByteVecU16__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

let impl_TlsByteVecU16__serialize_bytes_bytes (self: t_TlsByteVecU16)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error =
  match
    impl_TlsByteVecU16__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #u8 tls_serialized_len
    in
    (match
        Tls_codec.f_tls_serialize_bytes #u16
          #FStar.Tactics.Typeclasses.solve
          (Core.Result.impl__unwrap #u16
              #Core.Num.Error.t_TryFromIntError
              (Core.Convert.f_try_into #usize #u16 #FStar.Tactics.Typeclasses.solve byte_length
                <:
                Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
            <:
            u16)
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok length_vec ->
        let written:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_vec in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8
            #Alloc.Alloc.t_Global
            vec
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                length_vec
              <:
              t_Slice u8)
        in
        let bytes:t_Slice u8 = impl_TlsByteVecU16__as_slice self in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global vec bytes
        in
        let written:usize = written +! (Core.Slice.impl__len #u8 bytes <: usize) in
        (match
            impl_TlsByteVecU16__assert_written_bytes self tls_serialized_len written
            <:
            Core.Result.t_Result Prims.unit Tls_codec.t_Error
          with
          | Core.Result.Result_Ok _ ->
            Core.Result.Result_Ok vec
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_129: Tls_codec.t_Serialize t_TlsByteVecU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU16__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_132: Tls_codec.t_Size t_TlsByteVecU16 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU16) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU16) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU16) -> impl_TlsByteVecU16__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_131: Tls_codec.t_Serialize t_TlsByteVecU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU16__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_133: Tls_codec.t_Deserialize t_TlsByteVecU16 =
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
        (out1: (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error) =
        impl_TlsByteVecU16__deserialize_bytes #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU16 Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_134: Tls_codec.t_DeserializeBytes t_TlsByteVecU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsByteVecU16 & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) -> impl_TlsByteVecU16__deserialize_bytes_bytes bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_135: Tls_codec.t_SerializeBytes t_TlsByteVecU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_TlsByteVecU16) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_TlsByteVecU16)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_TlsByteVecU16) -> impl_TlsByteVecU16__serialize_bytes_bytes self
  }

type t_TlsByteVecU24 = { f_vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl_148: Core.Clone.t_Clone t_TlsByteVecU24 = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_149': Core.Fmt.t_Debug t_TlsByteVecU24

unfold
let impl_149 = impl_149'

/// Create a new `TlsVec` from a Rust Vec.
let impl_TlsByteVecU24__new (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_TlsByteVecU24 =
  { f_vec = vec } <: t_TlsByteVecU24

/// Create a new `TlsVec` from a slice.
let impl_TlsByteVecU24__from_slice
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Core.Clone.t_Clone u8)
      (slice: t_Slice u8)
    : t_TlsByteVecU24 = { f_vec = Alloc.Slice.impl__to_vec #u8 slice } <: t_TlsByteVecU24

/// Get the length of the vector.
let impl_TlsByteVecU24__len (self: t_TlsByteVecU24) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_TlsByteVecU24__as_slice (self: t_TlsByteVecU24) : t_Slice u8 =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_TlsByteVecU24__is_empty (self: t_TlsByteVecU24) : bool =
  Alloc.Vec.impl_1__is_empty #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_TlsByteVecU24__into_vec (self: t_TlsByteVecU24) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsByteVecU24 = { self with f_vec = tmp0 } <: t_TlsByteVecU24 in
  out

/// Add an element to this.
let impl_TlsByteVecU24__push (self: t_TlsByteVecU24) (value: u8) : t_TlsByteVecU24 =
  let self:t_TlsByteVecU24 =
    { self with f_vec = Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsByteVecU24
  in
  self

/// Remove the last element.
let impl_TlsByteVecU24__pop (self: t_TlsByteVecU24) : (t_TlsByteVecU24 & Core.Option.t_Option u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Core.Option.t_Option u8) =
    Alloc.Vec.impl_1__pop #u8 #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsByteVecU24 = { self with f_vec = tmp0 } <: t_TlsByteVecU24 in
  let hax_temp_output:Core.Option.t_Option u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU24 & Core.Option.t_Option u8)

/// Remove the element at `index`.
let impl_TlsByteVecU24__remove (self: t_TlsByteVecU24) (index: usize) : (t_TlsByteVecU24 & u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & u8) =
    Alloc.Vec.impl_1__remove #u8 #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsByteVecU24 = { self with f_vec = tmp0 } <: t_TlsByteVecU24 in
  let hax_temp_output:u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU24 & u8)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_TlsByteVecU24__get (self: t_TlsByteVecU24) (index: usize) : Core.Option.t_Option u8 =
  Core.Slice.impl__get #u8
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)
    index

/// Returns an iterator over the slice.
let impl_TlsByteVecU24__iter (self: t_TlsByteVecU24) : Core.Slice.Iter.t_Iter u8 =
  Core.Slice.impl__iter #u8
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)

/// Retains only the elements specified by the predicate.
let impl_TlsByteVecU24__retain
      (#v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Ops.Function.t_FnMut v_F u8)
      (self: t_TlsByteVecU24)
      (f: v_F)
    : t_TlsByteVecU24 =
  let self:t_TlsByteVecU24 =
    { self with f_vec = Alloc.Vec.impl_1__retain #u8 #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsByteVecU24
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_TlsByteVecU24__len_len (_: Prims.unit) : usize = mk_usize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_138: Core.Hash.t_Hash t_TlsByteVecU24 =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU24)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU24)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
      (self: t_TlsByteVecU24)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_139: Core.Ops.Index.t_Index t_TlsByteVecU24 usize =
  {
    f_Output = u8;
    f_index_pre = (fun (self: t_TlsByteVecU24) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsByteVecU24) (i: usize) (out: u8) -> true);
    f_index = fun (self: t_TlsByteVecU24) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_140: Core.Cmp.t_PartialEq t_TlsByteVecU24 t_TlsByteVecU24 =
  {
    f_eq_pre = (fun (self: t_TlsByteVecU24) (other: t_TlsByteVecU24) -> true);
    f_eq_post = (fun (self: t_TlsByteVecU24) (other: t_TlsByteVecU24) (out: bool) -> true);
    f_eq = fun (self: t_TlsByteVecU24) (other: t_TlsByteVecU24) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_147': Core.Cmp.t_Eq t_TlsByteVecU24

unfold
let impl_147 = impl_147'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_141: Core.Borrow.t_Borrow t_TlsByteVecU24 (t_Slice u8) =
  {
    f_borrow_pre = (fun (self: t_TlsByteVecU24) -> true);
    f_borrow_post = (fun (self: t_TlsByteVecU24) (out: t_Slice u8) -> true);
    f_borrow
    =
    fun (self: t_TlsByteVecU24) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_142: Core.Iter.Traits.Collect.t_FromIterator t_TlsByteVecU24 u8 =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsByteVecU24)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #u8
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsByteVecU24
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_143: Core.Convert.t_From t_TlsByteVecU24 (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_TlsByteVecU24) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_TlsByteVecU24__new v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_144: Core.Convert.t_From t_TlsByteVecU24 (t_Slice u8) =
  {
    f_from_pre = (fun (v: t_Slice u8) -> true);
    f_from_post = (fun (v: t_Slice u8) (out: t_TlsByteVecU24) -> true);
    f_from = fun (v: t_Slice u8) -> impl_TlsByteVecU24__from_slice v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_145: Core.Convert.t_From (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_TlsByteVecU24 =
  {
    f_from_pre = (fun (v: t_TlsByteVecU24) -> true);
    f_from_post = (fun (v: t_TlsByteVecU24) (out1: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsByteVecU24) ->
      let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsByteVecU24 = { v with f_vec = tmp0 } <: t_TlsByteVecU24 in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_146: Core.Default.t_Default t_TlsByteVecU24 =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsByteVecU24) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #u8 () } <: t_TlsByteVecU24
  }

let impl_TlsByteVecU24__assert_written_bytes
      (self: t_TlsByteVecU24)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_TlsByteVecU24__tls_serialized_byte_length (self: t_TlsByteVecU24) : usize =
  (Core.Slice.impl__len #u8 (impl_TlsByteVecU24__as_slice self <: t_Slice u8) <: usize) +!
  mk_usize 3

let impl_TlsByteVecU24__deserialize_bytes
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error) =
  let tmp0, out:(v_R & Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error with
  | Core.Result.Result_Ok hoist181 ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #Tls_codec.t_U24 #usize #FStar.Tactics.Typeclasses.solve hoist181
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
    then
      bytes,
      (Core.Result.Result_Err
        (Tls_codec.Error_DecodingError
          (Core.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                      (mk_usize 2)
                      (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                        Rust_primitives.Hax.array_of_list 3 list)
                      (let list =
                          [
                            Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                            Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
        Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
      <:
      (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
    else
      let result:t_TlsByteVecU24 =
        { f_vec = Alloc.Vec.from_elem #u8 (mk_u8 0) len } <: t_TlsByteVecU24
      in
      let tmp0, tmp1, out:(v_R & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes result.f_vec
      in
      let bytes:v_R = tmp0 in
      let result:t_TlsByteVecU24 = { result with f_vec = tmp1 } <: t_TlsByteVecU24 in
      (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          let hax_temp_output:Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error =
            Core.Result.Result_Ok result <: Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error
          in
          bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          bytes,
          (Core.Result.Result_Err
            (Core.Convert.f_from #Tls_codec.t_Error
                #Std.Io.Error.t_Error
                #FStar.Tactics.Typeclasses.solve
                err)
            <:
            Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)

let impl_TlsByteVecU24__deserialize_bytes_bytes (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error =
  match
    Tls_codec.f_tls_deserialize_bytes #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (Tls_codec.t_U24 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (type_len, remainder) ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Convert.t_Infallible
        (Core.Convert.f_try_into #Tls_codec.t_U24 #usize #FStar.Tactics.Typeclasses.solve type_len
          <:
          Core.Result.t_Result usize Core.Convert.t_Infallible)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
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
                          Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
      Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error
    else
      (match
          Core.Option.impl__ok_or #(t_Slice u8)
            #Tls_codec.t_Error
            (Core.Slice.impl__get #u8
                #(Core.Ops.Range.t_Range usize)
                bytes
                ({
                    Core.Ops.Range.f_start = mk_usize 3;
                    Core.Ops.Range.f_end = len +! mk_usize 3 <: usize
                  }
                  <:
                  Core.Ops.Range.t_Range usize)
              <:
              Core.Option.t_Option (t_Slice u8))
            (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
          <:
          Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
        with
        | Core.Result.Result_Ok vec ->
          let result:t_TlsByteVecU24 =
            { f_vec = Alloc.Slice.impl__to_vec #u8 vec } <: t_TlsByteVecU24
          in
          (match
              Core.Option.impl__ok_or #(t_Slice u8)
                #Tls_codec.t_Error
                (Core.Slice.impl__get #u8
                    #(Core.Ops.Range.t_RangeFrom usize)
                    remainder
                    ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                  <:
                  Core.Option.t_Option (t_Slice u8))
                (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
            with
            | Core.Result.Result_Ok hoist186 ->
              Core.Result.Result_Ok (result, hoist186 <: (t_TlsByteVecU24 & t_Slice u8))
              <:
              Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error
            | Core.Result.Result_Err err ->
              Core.Result.Result_Err err
              <:
              Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          Core.Result.Result_Err err
          <:
          Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_151: Tls_codec.t_Size t_TlsByteVecU24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU24) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU24) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU24) -> impl_TlsByteVecU24__tls_serialized_byte_length self
  }

let impl_TlsByteVecU24__get_content_lengths (self: t_TlsByteVecU24)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteVecU24 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 3 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #Tls_codec.t_U24
          #usize
          #FStar.Tactics.Typeclasses.solve
          Tls_codec.impl_U24__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_TlsByteVecU24__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU24)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_TlsByteVecU24__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #Tls_codec.t_U24
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #Tls_codec.t_U24
            #Tls_codec.t_Error
            (Core.Convert.f_try_from #Tls_codec.t_U24
                #usize
                #FStar.Tactics.Typeclasses.solve
                byte_length
              <:
              Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
          <:
          Tls_codec.t_U24)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_TlsByteVecU24__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist178 ->
            let written:usize = written +! hoist178 in
            (match
                impl_TlsByteVecU24__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

let impl_TlsByteVecU24__serialize_bytes_bytes (self: t_TlsByteVecU24)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error =
  match
    impl_TlsByteVecU24__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #u8 tls_serialized_len
    in
    (match
        Tls_codec.f_tls_serialize_bytes #Tls_codec.t_U24
          #FStar.Tactics.Typeclasses.solve
          (Core.Result.impl__unwrap #Tls_codec.t_U24
              #Tls_codec.t_Error
              (Core.Convert.f_try_into #usize
                  #Tls_codec.t_U24
                  #FStar.Tactics.Typeclasses.solve
                  byte_length
                <:
                Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
            <:
            Tls_codec.t_U24)
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok length_vec ->
        let written:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_vec in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8
            #Alloc.Alloc.t_Global
            vec
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                length_vec
              <:
              t_Slice u8)
        in
        let bytes:t_Slice u8 = impl_TlsByteVecU24__as_slice self in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global vec bytes
        in
        let written:usize = written +! (Core.Slice.impl__len #u8 bytes <: usize) in
        (match
            impl_TlsByteVecU24__assert_written_bytes self tls_serialized_len written
            <:
            Core.Result.t_Result Prims.unit Tls_codec.t_Error
          with
          | Core.Result.Result_Ok _ ->
            Core.Result.Result_Ok vec
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_150: Tls_codec.t_Serialize t_TlsByteVecU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU24__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_153: Tls_codec.t_Size t_TlsByteVecU24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU24) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU24) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU24) -> impl_TlsByteVecU24__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_152: Tls_codec.t_Serialize t_TlsByteVecU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU24__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_154: Tls_codec.t_Deserialize t_TlsByteVecU24 =
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
        (out1: (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error) =
        impl_TlsByteVecU24__deserialize_bytes #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU24 Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_155: Tls_codec.t_DeserializeBytes t_TlsByteVecU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsByteVecU24 & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) -> impl_TlsByteVecU24__deserialize_bytes_bytes bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_156: Tls_codec.t_SerializeBytes t_TlsByteVecU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_TlsByteVecU24) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_TlsByteVecU24)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_TlsByteVecU24) -> impl_TlsByteVecU24__serialize_bytes_bytes self
  }

type t_TlsByteVecU32 = { f_vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global }

let impl_169: Core.Clone.t_Clone t_TlsByteVecU32 = { f_clone = (fun x -> x) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_170': Core.Fmt.t_Debug t_TlsByteVecU32

unfold
let impl_170 = impl_170'

/// Create a new `TlsVec` from a Rust Vec.
let impl_TlsByteVecU32__new (vec: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) : t_TlsByteVecU32 =
  { f_vec = vec } <: t_TlsByteVecU32

/// Create a new `TlsVec` from a slice.
let impl_TlsByteVecU32__from_slice
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Core.Clone.t_Clone u8)
      (slice: t_Slice u8)
    : t_TlsByteVecU32 = { f_vec = Alloc.Slice.impl__to_vec #u8 slice } <: t_TlsByteVecU32

/// Get the length of the vector.
let impl_TlsByteVecU32__len (self: t_TlsByteVecU32) : usize =
  Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_TlsByteVecU32__as_slice (self: t_TlsByteVecU32) : t_Slice u8 =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_TlsByteVecU32__is_empty (self: t_TlsByteVecU32) : bool =
  Alloc.Vec.impl_1__is_empty #u8 #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_TlsByteVecU32__into_vec (self: t_TlsByteVecU32) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  =
    Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_TlsByteVecU32 = { self with f_vec = tmp0 } <: t_TlsByteVecU32 in
  out

/// Add an element to this.
let impl_TlsByteVecU32__push (self: t_TlsByteVecU32) (value: u8) : t_TlsByteVecU32 =
  let self:t_TlsByteVecU32 =
    { self with f_vec = Alloc.Vec.impl_1__push #u8 #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_TlsByteVecU32
  in
  self

/// Remove the last element.
let impl_TlsByteVecU32__pop (self: t_TlsByteVecU32) : (t_TlsByteVecU32 & Core.Option.t_Option u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Core.Option.t_Option u8) =
    Alloc.Vec.impl_1__pop #u8 #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_TlsByteVecU32 = { self with f_vec = tmp0 } <: t_TlsByteVecU32 in
  let hax_temp_output:Core.Option.t_Option u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU32 & Core.Option.t_Option u8)

/// Remove the element at `index`.
let impl_TlsByteVecU32__remove (self: t_TlsByteVecU32) (index: usize) : (t_TlsByteVecU32 & u8) =
  let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & u8) =
    Alloc.Vec.impl_1__remove #u8 #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_TlsByteVecU32 = { self with f_vec = tmp0 } <: t_TlsByteVecU32 in
  let hax_temp_output:u8 = out in
  self, hax_temp_output <: (t_TlsByteVecU32 & u8)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_TlsByteVecU32__get (self: t_TlsByteVecU32) (index: usize) : Core.Option.t_Option u8 =
  Core.Slice.impl__get #u8
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)
    index

/// Returns an iterator over the slice.
let impl_TlsByteVecU32__iter (self: t_TlsByteVecU32) : Core.Slice.Iter.t_Iter u8 =
  Core.Slice.impl__iter #u8
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice u8)

/// Retains only the elements specified by the predicate.
let impl_TlsByteVecU32__retain
      (#v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Ops.Function.t_FnMut v_F u8)
      (self: t_TlsByteVecU32)
      (f: v_F)
    : t_TlsByteVecU32 =
  let self:t_TlsByteVecU32 =
    { self with f_vec = Alloc.Vec.impl_1__retain #u8 #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_TlsByteVecU32
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_TlsByteVecU32__len_len (_: Prims.unit) : usize = mk_usize 4

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_159: Core.Hash.t_Hash t_TlsByteVecU32 =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU32)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
        (self: t_TlsByteVecU32)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Hash.t_Hasher v_H)
      (self: t_TlsByteVecU32)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_160: Core.Ops.Index.t_Index t_TlsByteVecU32 usize =
  {
    f_Output = u8;
    f_index_pre = (fun (self: t_TlsByteVecU32) (i: usize) -> true);
    f_index_post = (fun (self: t_TlsByteVecU32) (i: usize) (out: u8) -> true);
    f_index = fun (self: t_TlsByteVecU32) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_161: Core.Cmp.t_PartialEq t_TlsByteVecU32 t_TlsByteVecU32 =
  {
    f_eq_pre = (fun (self: t_TlsByteVecU32) (other: t_TlsByteVecU32) -> true);
    f_eq_post = (fun (self: t_TlsByteVecU32) (other: t_TlsByteVecU32) (out: bool) -> true);
    f_eq = fun (self: t_TlsByteVecU32) (other: t_TlsByteVecU32) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_168': Core.Cmp.t_Eq t_TlsByteVecU32

unfold
let impl_168 = impl_168'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_162: Core.Borrow.t_Borrow t_TlsByteVecU32 (t_Slice u8) =
  {
    f_borrow_pre = (fun (self: t_TlsByteVecU32) -> true);
    f_borrow_post = (fun (self: t_TlsByteVecU32) (out: t_Slice u8) -> true);
    f_borrow
    =
    fun (self: t_TlsByteVecU32) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_163: Core.Iter.Traits.Collect.t_FromIterator t_TlsByteVecU32 u8 =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_TlsByteVecU32)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #u8
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_TlsByteVecU32
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_164: Core.Convert.t_From t_TlsByteVecU32 (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from_post = (fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) (out: t_TlsByteVecU32) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> impl_TlsByteVecU32__new v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_165: Core.Convert.t_From t_TlsByteVecU32 (t_Slice u8) =
  {
    f_from_pre = (fun (v: t_Slice u8) -> true);
    f_from_post = (fun (v: t_Slice u8) (out: t_TlsByteVecU32) -> true);
    f_from = fun (v: t_Slice u8) -> impl_TlsByteVecU32__from_slice v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_166: Core.Convert.t_From (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_TlsByteVecU32 =
  {
    f_from_pre = (fun (v: t_TlsByteVecU32) -> true);
    f_from_post = (fun (v: t_TlsByteVecU32) (out1: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_TlsByteVecU32) ->
      let tmp0, out:(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_TlsByteVecU32 = { v with f_vec = tmp0 } <: t_TlsByteVecU32 in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_167: Core.Default.t_Default t_TlsByteVecU32 =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_TlsByteVecU32) -> true);
    f_default = fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #u8 () } <: t_TlsByteVecU32
  }

let impl_TlsByteVecU32__assert_written_bytes
      (self: t_TlsByteVecU32)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_TlsByteVecU32__tls_serialized_byte_length (self: t_TlsByteVecU32) : usize =
  (Core.Slice.impl__len #u8 (impl_TlsByteVecU32__as_slice self <: t_Slice u8) <: usize) +!
  mk_usize 4

let impl_TlsByteVecU32__deserialize_bytes
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error) =
  let tmp0, out:(v_R & Core.Result.t_Result u32 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u32 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u32 Tls_codec.t_Error with
  | Core.Result.Result_Ok hoist195 ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Num.Error.t_TryFromIntError
        (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve hoist195
          <:
          Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
    then
      bytes,
      (Core.Result.Result_Err
        (Tls_codec.Error_DecodingError
          (Core.Hint.must_use #Alloc.String.t_String
              (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                      (mk_usize 2)
                      (let list = ["Trying to allocate "; " bytes. Only "; " allowed."] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                        Rust_primitives.Hax.array_of_list 3 list)
                      (let list =
                          [
                            Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                            Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
        Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
      <:
      (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
    else
      let result:t_TlsByteVecU32 =
        { f_vec = Alloc.Vec.from_elem #u8 (mk_u8 0) len } <: t_TlsByteVecU32
      in
      let tmp0, tmp1, out:(v_R & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Core.Result.t_Result Prims.unit Std.Io.Error.t_Error) =
        Std.Io.f_read_exact #v_R #FStar.Tactics.Typeclasses.solve bytes result.f_vec
      in
      let bytes:v_R = tmp0 in
      let result:t_TlsByteVecU32 = { result with f_vec = tmp1 } <: t_TlsByteVecU32 in
      (match out <: Core.Result.t_Result Prims.unit Std.Io.Error.t_Error with
        | Core.Result.Result_Ok _ ->
          let hax_temp_output:Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error =
            Core.Result.Result_Ok result <: Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error
          in
          bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          bytes,
          (Core.Result.Result_Err
            (Core.Convert.f_from #Tls_codec.t_Error
                #Std.Io.Error.t_Error
                #FStar.Tactics.Typeclasses.solve
                err)
            <:
            Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
          <:
          (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes, (Core.Result.Result_Err err <: Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)

let impl_TlsByteVecU32__deserialize_bytes_bytes (bytes: t_Slice u8)
    : Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error =
  match
    Tls_codec.f_tls_deserialize_bytes #u32 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u32 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (type_len, remainder) ->
    let len:usize =
      Core.Result.impl__unwrap #usize
        #Core.Num.Error.t_TryFromIntError
        (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve type_len
          <:
          Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
    in
    if false && len >. (cast (Core.Num.impl_u16__MAX <: u16) <: usize)
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
                          Core.Fmt.Rt.impl__new_display #usize len <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #u16 Core.Num.impl_u16__MAX
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
      Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error
    else
      (match
          Core.Option.impl__ok_or #(t_Slice u8)
            #Tls_codec.t_Error
            (Core.Slice.impl__get #u8
                #(Core.Ops.Range.t_Range usize)
                bytes
                ({
                    Core.Ops.Range.f_start = mk_usize 4;
                    Core.Ops.Range.f_end = len +! mk_usize 4 <: usize
                  }
                  <:
                  Core.Ops.Range.t_Range usize)
              <:
              Core.Option.t_Option (t_Slice u8))
            (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
          <:
          Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
        with
        | Core.Result.Result_Ok vec ->
          let result:t_TlsByteVecU32 =
            { f_vec = Alloc.Slice.impl__to_vec #u8 vec } <: t_TlsByteVecU32
          in
          (match
              Core.Option.impl__ok_or #(t_Slice u8)
                #Tls_codec.t_Error
                (Core.Slice.impl__get #u8
                    #(Core.Ops.Range.t_RangeFrom usize)
                    remainder
                    ({ Core.Ops.Range.f_start = len } <: Core.Ops.Range.t_RangeFrom usize)
                  <:
                  Core.Option.t_Option (t_Slice u8))
                (Tls_codec.Error_EndOfStream <: Tls_codec.t_Error)
              <:
              Core.Result.t_Result (t_Slice u8) Tls_codec.t_Error
            with
            | Core.Result.Result_Ok hoist200 ->
              Core.Result.Result_Ok (result, hoist200 <: (t_TlsByteVecU32 & t_Slice u8))
              <:
              Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error
            | Core.Result.Result_Err err ->
              Core.Result.Result_Err err
              <:
              Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error)
        | Core.Result.Result_Err err ->
          Core.Result.Result_Err err
          <:
          Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_172: Tls_codec.t_Size t_TlsByteVecU32 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU32) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU32) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU32) -> impl_TlsByteVecU32__tls_serialized_byte_length self
  }

let impl_TlsByteVecU32__get_content_lengths (self: t_TlsByteVecU32)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteVecU32 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 4 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Num.Error.t_TryFromIntError
      (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u32__MAX
        <:
        Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_TlsByteVecU32__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU32)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_TlsByteVecU32__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u32
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u32
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u32 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
          <:
          u32)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_TlsByteVecU32__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist192 ->
            let written:usize = written +! hoist192 in
            (match
                impl_TlsByteVecU32__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

let impl_TlsByteVecU32__serialize_bytes_bytes (self: t_TlsByteVecU32)
    : Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error =
  match
    impl_TlsByteVecU32__get_content_lengths self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl__with_capacity #u8 tls_serialized_len
    in
    (match
        Tls_codec.f_tls_serialize_bytes #u32
          #FStar.Tactics.Typeclasses.solve
          (Core.Result.impl__unwrap #u32
              #Core.Num.Error.t_TryFromIntError
              (Core.Convert.f_try_into #usize #u32 #FStar.Tactics.Typeclasses.solve byte_length
                <:
                Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
            <:
            u32)
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
      with
      | Core.Result.Result_Ok length_vec ->
        let written:usize = Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global length_vec in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8
            #Alloc.Alloc.t_Global
            vec
            (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                length_vec
              <:
              t_Slice u8)
        in
        let bytes:t_Slice u8 = impl_TlsByteVecU32__as_slice self in
        let vec:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global vec bytes
        in
        let written:usize = written +! (Core.Slice.impl__len #u8 bytes <: usize) in
        (match
            impl_TlsByteVecU32__assert_written_bytes self tls_serialized_len written
            <:
            Core.Result.t_Result Prims.unit Tls_codec.t_Error
          with
          | Core.Result.Result_Ok _ ->
            Core.Result.Result_Ok vec
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error
          | Core.Result.Result_Err err ->
            Core.Result.Result_Err err
            <:
            Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
      | Core.Result.Result_Err err ->
        Core.Result.Result_Err err
        <:
        Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_171: Tls_codec.t_Serialize t_TlsByteVecU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU32__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_174: Tls_codec.t_Size t_TlsByteVecU32 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteVecU32) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteVecU32) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteVecU32) -> impl_TlsByteVecU32__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_173: Tls_codec.t_Serialize t_TlsByteVecU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteVecU32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteVecU32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_TlsByteVecU32__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_175: Tls_codec.t_Deserialize t_TlsByteVecU32 =
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
        (out1: (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error) =
        impl_TlsByteVecU32__deserialize_bytes #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error = out in
      bytes, hax_temp_output <: (v_R & Core.Result.t_Result t_TlsByteVecU32 Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_176: Tls_codec.t_DeserializeBytes t_TlsByteVecU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_TlsByteVecU32 & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes
    =
    fun (bytes: t_Slice u8) -> impl_TlsByteVecU32__deserialize_bytes_bytes bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_177: Tls_codec.t_SerializeBytes t_TlsByteVecU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_bytes_pre = (fun (self: t_TlsByteVecU32) -> true);
    f_tls_serialize_bytes_post
    =
    (fun
        (self: t_TlsByteVecU32)
        (out: Core.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Tls_codec.t_Error)
        ->
        true);
    f_tls_serialize_bytes
    =
    fun (self: t_TlsByteVecU32) -> impl_TlsByteVecU32__serialize_bytes_bytes self
  }

type t_SecretTlsVecU8 (v_T: Type0) {| i1: Zeroize.t_Zeroize v_T |} = {
  f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_196': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Fmt.t_Debug (t_SecretTlsVecU8 v_T)

unfold
let impl_196
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_196' #v_T #i1 #i2

/// Create a new `TlsVec` from a Rust Vec.
let impl_185__new
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : t_SecretTlsVecU8 v_T = { f_vec = vec } <: t_SecretTlsVecU8 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_184
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_SecretTlsVecU8 v_T) =
  {
    f_clone_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_clone_post = (fun (self: t_SecretTlsVecU8 v_T) (out: t_SecretTlsVecU8 v_T) -> true);
    f_clone
    =
    fun (self: t_SecretTlsVecU8 v_T) ->
      impl_185__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_185__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_SecretTlsVecU8 v_T = { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_SecretTlsVecU8 v_T

/// Get the length of the vector.
let impl_185__len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : usize = Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_185__as_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_185__is_empty
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : bool = Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_185__into_vec
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_SecretTlsVecU8 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU8 v_T in
  out

/// Add an element to this.
let impl_185__push
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
      (value: v_T)
    : t_SecretTlsVecU8 v_T =
  let self:t_SecretTlsVecU8 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_SecretTlsVecU8 v_T
  in
  self

/// Remove the last element.
let impl_185__pop
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : (t_SecretTlsVecU8 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_SecretTlsVecU8 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU8 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU8 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_185__remove
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
      (index: usize)
    : (t_SecretTlsVecU8 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_SecretTlsVecU8 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU8 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU8 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_185__get
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
      (index: usize)
    : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_185__iter
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_185__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_SecretTlsVecU8 v_T)
      (f: v_F)
    : t_SecretTlsVecU8 v_T =
  let self:t_SecretTlsVecU8 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_SecretTlsVecU8 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_185__len_len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (_: Prims.unit)
    : usize = mk_usize 1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_186
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_SecretTlsVecU8 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU8 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU8 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
      (self: t_SecretTlsVecU8 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_187 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Index.t_Index (t_SecretTlsVecU8 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_SecretTlsVecU8 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_SecretTlsVecU8 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_SecretTlsVecU8 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_188
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_SecretTlsVecU8 v_T) (t_SecretTlsVecU8 v_T) =
  {
    f_eq_pre = (fun (self: t_SecretTlsVecU8 v_T) (other: t_SecretTlsVecU8 v_T) -> true);
    f_eq_post = (fun (self: t_SecretTlsVecU8 v_T) (other: t_SecretTlsVecU8 v_T) (out: bool) -> true);
    f_eq
    =
    fun (self: t_SecretTlsVecU8 v_T) (other: t_SecretTlsVecU8 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_195': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Cmp.t_Eq (t_SecretTlsVecU8 v_T)

unfold
let impl_195
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_195' #v_T #i1 #i2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_189 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Borrow.t_Borrow (t_SecretTlsVecU8 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_borrow_post = (fun (self: t_SecretTlsVecU8 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_SecretTlsVecU8 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_190 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Iter.Traits.Collect.t_FromIterator (t_SecretTlsVecU8 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_SecretTlsVecU8 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_SecretTlsVecU8 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_191 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (t_SecretTlsVecU8 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post
    =
    (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_SecretTlsVecU8 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_185__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_192
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_SecretTlsVecU8 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_SecretTlsVecU8 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_185__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_193 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_SecretTlsVecU8 v_T) =
  {
    f_from_pre = (fun (v: t_SecretTlsVecU8 v_T) -> true);
    f_from_post
    =
    (fun (v: t_SecretTlsVecU8 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_SecretTlsVecU8 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_SecretTlsVecU8 v_T = { v with f_vec = tmp0 } <: t_SecretTlsVecU8 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_194 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Default.t_Default (t_SecretTlsVecU8 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_SecretTlsVecU8 v_T) -> true);
    f_default
    =
    fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU8 v_T
  }

let impl_178__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_179__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_185__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 1)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_198
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU8 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU8 v_T) -> impl_179__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_200
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU8 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU8 v_T) -> impl_179__tls_serialized_length #v_T self
  }

let impl_178__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU8 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_SecretTlsVecU8 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 1 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u8__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_178__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU8 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_178__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u8
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u8
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u8 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
          <:
          u8)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_185__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist206 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist206 <: (v_W & usize))
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
            match
              impl_178__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_197
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_178__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_199
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_178__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_180__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error) =
  let result:t_SecretTlsVecU8 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU8 v_T
  in
  let tmp0, out:(v_R & Core.Result.t_Result u8 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u8 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u8 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU8 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU8 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU8 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_SecretTlsVecU8 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU8 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU8 v_T = impl_185__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_SecretTlsVecU8 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU8 v_T)))
                  (v_R & usize & t_SecretTlsVecU8 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_SecretTlsVecU8 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU8 v_T)))
                  (v_R & usize & t_SecretTlsVecU8 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
          (v_R & usize & t_SecretTlsVecU8 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result
          <:
          Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output
        <:
        (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes,
    (Core.Result.Result_Err err <: Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_201
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_SecretTlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error) =
        impl_180__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (t_SecretTlsVecU8 v_T) Tls_codec.t_Error)
  }

let impl_181__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_SecretTlsVecU8 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU8 v_T
  in
  match
    Tls_codec.f_tls_deserialize_bytes #u8 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u8 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u8 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU8 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU8 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU8 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU8 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU8 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU8 v_T = impl_185__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU8 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU8 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU8 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU8 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU8 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU8 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_SecretTlsVecU8 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_SecretTlsVecU8 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_202
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_SecretTlsVecU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_SecretTlsVecU8 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_181__deserialize_bytes #v_T bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_182 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Zeroize.t_Zeroize (t_SecretTlsVecU8 v_T) =
  {
    f_zeroize_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_zeroize_post = (fun (self: t_SecretTlsVecU8 v_T) (out: t_SecretTlsVecU8 v_T) -> true);
    f_zeroize
    =
    fun (self: t_SecretTlsVecU8 v_T) ->
      let self:t_SecretTlsVecU8 v_T =
        {
          self with
          f_vec
          =
          Zeroize.f_zeroize #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
        }
        <:
        t_SecretTlsVecU8 v_T
      in
      self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_183 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Drop.t_Drop (t_SecretTlsVecU8 v_T) =
  {
    f_drop_pre = (fun (self: t_SecretTlsVecU8 v_T) -> true);
    f_drop_post = (fun (self: t_SecretTlsVecU8 v_T) (out: t_SecretTlsVecU8 v_T) -> true);
    f_drop
    =
    fun (self: t_SecretTlsVecU8 v_T) ->
      let self:t_SecretTlsVecU8 v_T =
        Zeroize.f_zeroize #(t_SecretTlsVecU8 v_T) #FStar.Tactics.Typeclasses.solve self
      in
      self
  }

type t_SecretTlsVecU16 (v_T: Type0) {| i1: Zeroize.t_Zeroize v_T |} = {
  f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_221': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Fmt.t_Debug (t_SecretTlsVecU16 v_T)

unfold
let impl_221
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_221' #v_T #i1 #i2

/// Create a new `TlsVec` from a Rust Vec.
let impl_210__new
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : t_SecretTlsVecU16 v_T = { f_vec = vec } <: t_SecretTlsVecU16 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_209
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_SecretTlsVecU16 v_T) =
  {
    f_clone_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_clone_post = (fun (self: t_SecretTlsVecU16 v_T) (out: t_SecretTlsVecU16 v_T) -> true);
    f_clone
    =
    fun (self: t_SecretTlsVecU16 v_T) ->
      impl_210__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_210__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_SecretTlsVecU16 v_T =
  { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_SecretTlsVecU16 v_T

/// Get the length of the vector.
let impl_210__len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : usize = Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_210__as_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_210__is_empty
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : bool = Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_210__into_vec
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_SecretTlsVecU16 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU16 v_T in
  out

/// Add an element to this.
let impl_210__push
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
      (value: v_T)
    : t_SecretTlsVecU16 v_T =
  let self:t_SecretTlsVecU16 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_SecretTlsVecU16 v_T
  in
  self

/// Remove the last element.
let impl_210__pop
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : (t_SecretTlsVecU16 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_SecretTlsVecU16 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU16 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU16 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_210__remove
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
      (index: usize)
    : (t_SecretTlsVecU16 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_SecretTlsVecU16 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU16 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU16 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_210__get
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
      (index: usize)
    : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_210__iter
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_210__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_SecretTlsVecU16 v_T)
      (f: v_F)
    : t_SecretTlsVecU16 v_T =
  let self:t_SecretTlsVecU16 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_SecretTlsVecU16 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_210__len_len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (_: Prims.unit)
    : usize = mk_usize 2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_211
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_SecretTlsVecU16 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU16 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU16 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
      (self: t_SecretTlsVecU16 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_212 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Index.t_Index (t_SecretTlsVecU16 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_SecretTlsVecU16 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_SecretTlsVecU16 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_SecretTlsVecU16 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_213
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_SecretTlsVecU16 v_T) (t_SecretTlsVecU16 v_T) =
  {
    f_eq_pre = (fun (self: t_SecretTlsVecU16 v_T) (other: t_SecretTlsVecU16 v_T) -> true);
    f_eq_post
    =
    (fun (self: t_SecretTlsVecU16 v_T) (other: t_SecretTlsVecU16 v_T) (out: bool) -> true);
    f_eq
    =
    fun (self: t_SecretTlsVecU16 v_T) (other: t_SecretTlsVecU16 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_220': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Cmp.t_Eq (t_SecretTlsVecU16 v_T)

unfold
let impl_220
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_220' #v_T #i1 #i2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_214 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Borrow.t_Borrow (t_SecretTlsVecU16 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_borrow_post = (fun (self: t_SecretTlsVecU16 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_SecretTlsVecU16 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_215 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Iter.Traits.Collect.t_FromIterator (t_SecretTlsVecU16 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_SecretTlsVecU16 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_SecretTlsVecU16 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_216 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (t_SecretTlsVecU16 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post
    =
    (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_SecretTlsVecU16 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_210__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_217
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_SecretTlsVecU16 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_SecretTlsVecU16 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_210__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_218 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_SecretTlsVecU16 v_T) =
  {
    f_from_pre = (fun (v: t_SecretTlsVecU16 v_T) -> true);
    f_from_post
    =
    (fun (v: t_SecretTlsVecU16 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_SecretTlsVecU16 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_SecretTlsVecU16 v_T = { v with f_vec = tmp0 } <: t_SecretTlsVecU16 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_219 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Default.t_Default (t_SecretTlsVecU16 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_SecretTlsVecU16 v_T) -> true);
    f_default
    =
    fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU16 v_T
  }

let impl_203__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_204__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_210__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 2)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_223
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU16 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU16 v_T) -> impl_204__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_225
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU16 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU16 v_T) -> impl_204__tls_serialized_length #v_T self
  }

let impl_203__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU16 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_SecretTlsVecU16 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 2 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u16__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_203__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU16 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_203__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u16
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u16
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u16 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
          <:
          u16)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_210__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist214 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist214 <: (v_W & usize))
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
            match
              impl_203__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_222
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_203__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_224
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_203__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_205__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error) =
  let result:t_SecretTlsVecU16 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU16 v_T
  in
  let tmp0, out:(v_R & Core.Result.t_Result u16 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u16 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u16 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU16 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU16 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU16 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_SecretTlsVecU16 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU16 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU16 v_T = impl_210__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_SecretTlsVecU16 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU16 v_T)))
                  (v_R & usize & t_SecretTlsVecU16 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_SecretTlsVecU16 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU16 v_T)))
                  (v_R & usize & t_SecretTlsVecU16 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
          (v_R & usize & t_SecretTlsVecU16 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result
          <:
          Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output
        <:
        (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes,
    (Core.Result.Result_Err err <: Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_226
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_SecretTlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error) =
        impl_205__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (t_SecretTlsVecU16 v_T) Tls_codec.t_Error)
  }

let impl_206__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_SecretTlsVecU16 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU16 v_T
  in
  match
    Tls_codec.f_tls_deserialize_bytes #u16 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u16 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u16 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU16 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU16 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU16 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU16 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU16 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU16 v_T = impl_210__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU16 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU16 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU16 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU16 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU16 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU16 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_SecretTlsVecU16 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_SecretTlsVecU16 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_227
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_SecretTlsVecU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_SecretTlsVecU16 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_206__deserialize_bytes #v_T bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_207 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Zeroize.t_Zeroize (t_SecretTlsVecU16 v_T) =
  {
    f_zeroize_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_zeroize_post = (fun (self: t_SecretTlsVecU16 v_T) (out: t_SecretTlsVecU16 v_T) -> true);
    f_zeroize
    =
    fun (self: t_SecretTlsVecU16 v_T) ->
      let self:t_SecretTlsVecU16 v_T =
        {
          self with
          f_vec
          =
          Zeroize.f_zeroize #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
        }
        <:
        t_SecretTlsVecU16 v_T
      in
      self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_208 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Drop.t_Drop (t_SecretTlsVecU16 v_T) =
  {
    f_drop_pre = (fun (self: t_SecretTlsVecU16 v_T) -> true);
    f_drop_post = (fun (self: t_SecretTlsVecU16 v_T) (out: t_SecretTlsVecU16 v_T) -> true);
    f_drop
    =
    fun (self: t_SecretTlsVecU16 v_T) ->
      let self:t_SecretTlsVecU16 v_T =
        Zeroize.f_zeroize #(t_SecretTlsVecU16 v_T) #FStar.Tactics.Typeclasses.solve self
      in
      self
  }

type t_SecretTlsVecU24 (v_T: Type0) {| i1: Zeroize.t_Zeroize v_T |} = {
  f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_246': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Fmt.t_Debug (t_SecretTlsVecU24 v_T)

unfold
let impl_246
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_246' #v_T #i1 #i2

/// Create a new `TlsVec` from a Rust Vec.
let impl_235__new
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : t_SecretTlsVecU24 v_T = { f_vec = vec } <: t_SecretTlsVecU24 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_234
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_SecretTlsVecU24 v_T) =
  {
    f_clone_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_clone_post = (fun (self: t_SecretTlsVecU24 v_T) (out: t_SecretTlsVecU24 v_T) -> true);
    f_clone
    =
    fun (self: t_SecretTlsVecU24 v_T) ->
      impl_235__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_235__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_SecretTlsVecU24 v_T =
  { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_SecretTlsVecU24 v_T

/// Get the length of the vector.
let impl_235__len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : usize = Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_235__as_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_235__is_empty
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : bool = Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_235__into_vec
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_SecretTlsVecU24 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU24 v_T in
  out

/// Add an element to this.
let impl_235__push
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
      (value: v_T)
    : t_SecretTlsVecU24 v_T =
  let self:t_SecretTlsVecU24 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_SecretTlsVecU24 v_T
  in
  self

/// Remove the last element.
let impl_235__pop
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : (t_SecretTlsVecU24 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_SecretTlsVecU24 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU24 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU24 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_235__remove
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
      (index: usize)
    : (t_SecretTlsVecU24 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_SecretTlsVecU24 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU24 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU24 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_235__get
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
      (index: usize)
    : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_235__iter
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_235__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_SecretTlsVecU24 v_T)
      (f: v_F)
    : t_SecretTlsVecU24 v_T =
  let self:t_SecretTlsVecU24 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_SecretTlsVecU24 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_235__len_len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (_: Prims.unit)
    : usize = mk_usize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_236
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_SecretTlsVecU24 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU24 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU24 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
      (self: t_SecretTlsVecU24 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_237 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Index.t_Index (t_SecretTlsVecU24 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_SecretTlsVecU24 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_SecretTlsVecU24 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_SecretTlsVecU24 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_238
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_SecretTlsVecU24 v_T) (t_SecretTlsVecU24 v_T) =
  {
    f_eq_pre = (fun (self: t_SecretTlsVecU24 v_T) (other: t_SecretTlsVecU24 v_T) -> true);
    f_eq_post
    =
    (fun (self: t_SecretTlsVecU24 v_T) (other: t_SecretTlsVecU24 v_T) (out: bool) -> true);
    f_eq
    =
    fun (self: t_SecretTlsVecU24 v_T) (other: t_SecretTlsVecU24 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_245': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Cmp.t_Eq (t_SecretTlsVecU24 v_T)

unfold
let impl_245
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_245' #v_T #i1 #i2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_239 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Borrow.t_Borrow (t_SecretTlsVecU24 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_borrow_post = (fun (self: t_SecretTlsVecU24 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_SecretTlsVecU24 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_240 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Iter.Traits.Collect.t_FromIterator (t_SecretTlsVecU24 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_SecretTlsVecU24 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_SecretTlsVecU24 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_241 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (t_SecretTlsVecU24 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post
    =
    (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_SecretTlsVecU24 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_235__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_242
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_SecretTlsVecU24 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_SecretTlsVecU24 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_235__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_243 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_SecretTlsVecU24 v_T) =
  {
    f_from_pre = (fun (v: t_SecretTlsVecU24 v_T) -> true);
    f_from_post
    =
    (fun (v: t_SecretTlsVecU24 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_SecretTlsVecU24 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_SecretTlsVecU24 v_T = { v with f_vec = tmp0 } <: t_SecretTlsVecU24 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_244 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Default.t_Default (t_SecretTlsVecU24 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_SecretTlsVecU24 v_T) -> true);
    f_default
    =
    fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU24 v_T
  }

let impl_228__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_229__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_235__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 3)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_248
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU24 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU24 v_T) -> impl_229__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_250
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU24 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU24 v_T) -> impl_229__tls_serialized_length #v_T self
  }

let impl_228__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU24 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_SecretTlsVecU24 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 3 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #Tls_codec.t_U24
          #usize
          #FStar.Tactics.Typeclasses.solve
          Tls_codec.impl_U24__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_228__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU24 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_228__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #Tls_codec.t_U24
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #Tls_codec.t_U24
            #Tls_codec.t_Error
            (Core.Convert.f_try_from #Tls_codec.t_U24
                #usize
                #FStar.Tactics.Typeclasses.solve
                byte_length
              <:
              Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
          <:
          Tls_codec.t_U24)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_235__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist222 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist222 <: (v_W & usize))
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
            match
              impl_228__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_247
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_228__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_249
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_228__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_230__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error) =
  let result:t_SecretTlsVecU24 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU24 v_T
  in
  let tmp0, out:(v_R & Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize =
      Tls_codec.f_tls_serialized_len #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve len
    in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU24 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #Tls_codec.t_U24
                      #usize
                      #FStar.Tactics.Typeclasses.solve
                      len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU24 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU24 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_SecretTlsVecU24 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU24 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU24 v_T = impl_235__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_SecretTlsVecU24 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU24 v_T)))
                  (v_R & usize & t_SecretTlsVecU24 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_SecretTlsVecU24 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU24 v_T)))
                  (v_R & usize & t_SecretTlsVecU24 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
          (v_R & usize & t_SecretTlsVecU24 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result
          <:
          Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output
        <:
        (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes,
    (Core.Result.Result_Err err <: Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_251
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_SecretTlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error) =
        impl_230__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (t_SecretTlsVecU24 v_T) Tls_codec.t_Error)
  }

let impl_231__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_SecretTlsVecU24 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU24 v_T
  in
  match
    Tls_codec.f_tls_deserialize_bytes #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (Tls_codec.t_U24 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize =
      Tls_codec.f_tls_serialized_len #Tls_codec.t_U24 #FStar.Tactics.Typeclasses.solve len
    in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU24 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Convert.t_Infallible
                  (Core.Convert.f_try_into #Tls_codec.t_U24
                      #usize
                      #FStar.Tactics.Typeclasses.solve
                      len
                    <:
                    Core.Result.t_Result usize Core.Convert.t_Infallible)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU24 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU24 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU24 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU24 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU24 v_T = impl_235__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU24 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU24 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU24 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU24 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU24 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU24 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_SecretTlsVecU24 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_SecretTlsVecU24 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_252
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_SecretTlsVecU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_SecretTlsVecU24 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_231__deserialize_bytes #v_T bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_232 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Zeroize.t_Zeroize (t_SecretTlsVecU24 v_T) =
  {
    f_zeroize_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_zeroize_post = (fun (self: t_SecretTlsVecU24 v_T) (out: t_SecretTlsVecU24 v_T) -> true);
    f_zeroize
    =
    fun (self: t_SecretTlsVecU24 v_T) ->
      let self:t_SecretTlsVecU24 v_T =
        {
          self with
          f_vec
          =
          Zeroize.f_zeroize #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
        }
        <:
        t_SecretTlsVecU24 v_T
      in
      self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_233 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Drop.t_Drop (t_SecretTlsVecU24 v_T) =
  {
    f_drop_pre = (fun (self: t_SecretTlsVecU24 v_T) -> true);
    f_drop_post = (fun (self: t_SecretTlsVecU24 v_T) (out: t_SecretTlsVecU24 v_T) -> true);
    f_drop
    =
    fun (self: t_SecretTlsVecU24 v_T) ->
      let self:t_SecretTlsVecU24 v_T =
        Zeroize.f_zeroize #(t_SecretTlsVecU24 v_T) #FStar.Tactics.Typeclasses.solve self
      in
      self
  }

type t_SecretTlsVecU32 (v_T: Type0) {| i1: Zeroize.t_Zeroize v_T |} = {
  f_vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_271': #v_T: Type0 -> {| i1: Core.Fmt.t_Debug v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Fmt.t_Debug (t_SecretTlsVecU32 v_T)

unfold
let impl_271
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Fmt.t_Debug v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_271' #v_T #i1 #i2

/// Create a new `TlsVec` from a Rust Vec.
let impl_260__new
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (vec: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    : t_SecretTlsVecU32 v_T = { f_vec = vec } <: t_SecretTlsVecU32 v_T

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_259
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Clone.t_Clone (t_SecretTlsVecU32 v_T) =
  {
    f_clone_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_clone_post = (fun (self: t_SecretTlsVecU32 v_T) (out: t_SecretTlsVecU32 v_T) -> true);
    f_clone
    =
    fun (self: t_SecretTlsVecU32 v_T) ->
      impl_260__new #v_T
        (Core.Clone.f_clone #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
          <:
          Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
  }

/// Create a new `TlsVec` from a slice.
let impl_260__from_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
      (slice: t_Slice v_T)
    : t_SecretTlsVecU32 v_T =
  { f_vec = Alloc.Slice.impl__to_vec #v_T slice } <: t_SecretTlsVecU32 v_T

/// Get the length of the vector.
let impl_260__len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : usize = Alloc.Vec.impl_1__len #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get a slice to the raw vector.
let impl_260__as_slice
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : t_Slice v_T =
  Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
    #FStar.Tactics.Typeclasses.solve
    self.f_vec

/// Check if the vector is empty.
let impl_260__is_empty
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : bool = Alloc.Vec.impl_1__is_empty #v_T #Alloc.Alloc.t_Global self.f_vec

/// Get the underlying vector and consume this.
let impl_260__into_vec
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global
  ) =
    Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) self.f_vec
  in
  let self:t_SecretTlsVecU32 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU32 v_T in
  out

/// Add an element to this.
let impl_260__push
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
      (value: v_T)
    : t_SecretTlsVecU32 v_T =
  let self:t_SecretTlsVecU32 v_T =
    { self with f_vec = Alloc.Vec.impl_1__push #v_T #Alloc.Alloc.t_Global self.f_vec value }
    <:
    t_SecretTlsVecU32 v_T
  in
  self

/// Remove the last element.
let impl_260__pop
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : (t_SecretTlsVecU32 v_T & Core.Option.t_Option v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & Core.Option.t_Option v_T) =
    Alloc.Vec.impl_1__pop #v_T #Alloc.Alloc.t_Global self.f_vec
  in
  let self:t_SecretTlsVecU32 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU32 v_T in
  let hax_temp_output:Core.Option.t_Option v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU32 v_T & Core.Option.t_Option v_T)

/// Remove the element at `index`.
let impl_260__remove
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
      (index: usize)
    : (t_SecretTlsVecU32 v_T & v_T) =
  let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global & v_T) =
    Alloc.Vec.impl_1__remove #v_T #Alloc.Alloc.t_Global self.f_vec index
  in
  let self:t_SecretTlsVecU32 v_T = { self with f_vec = tmp0 } <: t_SecretTlsVecU32 v_T in
  let hax_temp_output:v_T = out in
  self, hax_temp_output <: (t_SecretTlsVecU32 v_T & v_T)

/// Returns a reference to an element or subslice depending on the type of index.
/// XXX: implement SliceIndex instead
let impl_260__get
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
      (index: usize)
    : Core.Option.t_Option v_T =
  Core.Slice.impl__get #v_T
    #usize
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)
    index

/// Returns an iterator over the slice.
let impl_260__iter
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : Core.Slice.Iter.t_Iter v_T =
  Core.Slice.impl__iter #v_T
    (Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
      <:
      t_Slice v_T)

/// Retains only the elements specified by the predicate.
let impl_260__retain
      (#v_T #v_F: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Ops.Function.t_FnMut v_F v_T)
      (self: t_SecretTlsVecU32 v_T)
      (f: v_F)
    : t_SecretTlsVecU32 v_T =
  let self:t_SecretTlsVecU32 v_T =
    { self with f_vec = Alloc.Vec.impl_1__retain #v_T #Alloc.Alloc.t_Global #v_F self.f_vec f }
    <:
    t_SecretTlsVecU32 v_T
  in
  self

/// Get the number of bytes used for the length encoding.
let impl_260__len_len
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (_: Prims.unit)
    : usize = mk_usize 4

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_261
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Hash.t_Hash v_T)
    : Core.Hash.t_Hash (t_SecretTlsVecU32 v_T) =
  {
    f_hash_pre
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU32 v_T)
        (state: v_H)
        ->
        true);
    f_hash_post
    =
    (fun
        (#v_H: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
        (self: t_SecretTlsVecU32 v_T)
        (state: v_H)
        (out: v_H)
        ->
        true);
    f_hash
    =
    fun
      (#v_H: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Core.Hash.t_Hasher v_H)
      (self: t_SecretTlsVecU32 v_T)
      (state: v_H)
      ->
      let state:v_H =
        Core.Hash.f_hash #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #v_H
          self.f_vec
          state
      in
      state
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_262 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Index.t_Index (t_SecretTlsVecU32 v_T) usize =
  {
    f_Output = v_T;
    f_index_pre = (fun (self: t_SecretTlsVecU32 v_T) (i: usize) -> true);
    f_index_post = (fun (self: t_SecretTlsVecU32 v_T) (i: usize) (out: v_T) -> true);
    f_index = fun (self: t_SecretTlsVecU32 v_T) (i: usize) -> self.f_vec.[ i ]
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_263
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Cmp.t_PartialEq v_T v_T)
    : Core.Cmp.t_PartialEq (t_SecretTlsVecU32 v_T) (t_SecretTlsVecU32 v_T) =
  {
    f_eq_pre = (fun (self: t_SecretTlsVecU32 v_T) (other: t_SecretTlsVecU32 v_T) -> true);
    f_eq_post
    =
    (fun (self: t_SecretTlsVecU32 v_T) (other: t_SecretTlsVecU32 v_T) (out: bool) -> true);
    f_eq
    =
    fun (self: t_SecretTlsVecU32 v_T) (other: t_SecretTlsVecU32 v_T) -> self.f_vec =. other.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_270': #v_T: Type0 -> {| i1: Core.Cmp.t_Eq v_T |} -> {| i2: Zeroize.t_Zeroize v_T |}
  -> Core.Cmp.t_Eq (t_SecretTlsVecU32 v_T)

unfold
let impl_270
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Core.Cmp.t_Eq v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
     = impl_270' #v_T #i1 #i2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_264 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Borrow.t_Borrow (t_SecretTlsVecU32 v_T) (t_Slice v_T) =
  {
    f_borrow_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_borrow_post = (fun (self: t_SecretTlsVecU32 v_T) (out: t_Slice v_T) -> true);
    f_borrow
    =
    fun (self: t_SecretTlsVecU32 v_T) ->
      Core.Ops.Deref.f_deref #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
        #FStar.Tactics.Typeclasses.solve
        self.f_vec
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_265 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Iter.Traits.Collect.t_FromIterator (t_SecretTlsVecU32 v_T) v_T =
  {
    f_from_iter_pre
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        ->
        true);
    f_from_iter_post
    =
    (fun
        (#v_I: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
        (iter: v_I)
        (out: t_SecretTlsVecU32 v_T)
        ->
        true);
    f_from_iter
    =
    fun
      (#v_I: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Core.Iter.Traits.Collect.t_IntoIterator v_I)
      (iter: v_I)
      ->
      let vec:Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global =
        Core.Iter.Traits.Collect.f_from_iter #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
          #v_T
          #FStar.Tactics.Typeclasses.solve
          #v_I
          iter
      in
      { f_vec = vec } <: t_SecretTlsVecU32 v_T
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_266 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (t_SecretTlsVecU32 v_T) (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
  {
    f_from_pre = (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from_post
    =
    (fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (out: t_SecretTlsVecU32 v_T) -> true);
    f_from = fun (v: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> impl_260__new #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_267
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Core.Clone.t_Clone v_T)
    : Core.Convert.t_From (t_SecretTlsVecU32 v_T) (t_Slice v_T) =
  {
    f_from_pre = (fun (v: t_Slice v_T) -> true);
    f_from_post = (fun (v: t_Slice v_T) (out: t_SecretTlsVecU32 v_T) -> true);
    f_from = fun (v: t_Slice v_T) -> impl_260__from_slice #v_T v
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_268 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Convert.t_From (Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) (t_SecretTlsVecU32 v_T) =
  {
    f_from_pre = (fun (v: t_SecretTlsVecU32 v_T) -> true);
    f_from_post
    =
    (fun (v: t_SecretTlsVecU32 v_T) (out1: Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) -> true);
    f_from
    =
    fun (v: t_SecretTlsVecU32 v_T) ->
      let tmp0, out:(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) =
        Core.Mem.take #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global) v.f_vec
      in
      let v:t_SecretTlsVecU32 v_T = { v with f_vec = tmp0 } <: t_SecretTlsVecU32 v_T in
      out
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_269 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Default.t_Default (t_SecretTlsVecU32 v_T) =
  {
    f_default_pre = (fun (_: Prims.unit) -> true);
    f_default_post = (fun (_: Prims.unit) (out: t_SecretTlsVecU32 v_T) -> true);
    f_default
    =
    fun (_: Prims.unit) -> { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU32 v_T
  }

let impl_253__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_254__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_260__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 4)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_273
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU32 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU32 v_T) -> impl_254__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_275
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_SecretTlsVecU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_SecretTlsVecU32 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_SecretTlsVecU32 v_T) -> impl_254__tls_serialized_length #v_T self
  }

let impl_253__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (self: t_SecretTlsVecU32 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_SecretTlsVecU32 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 4 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Num.Error.t_TryFromIntError
      (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u32__MAX
        <:
        Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_253__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU32 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_253__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u32
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u32
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u32 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
          <:
          u32)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_260__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist230 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist230 <: (v_W & usize))
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
            match
              impl_253__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_272
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_253__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_274
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_SecretTlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
        (self: t_SecretTlsVecU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Write v_W)
      (self: t_SecretTlsVecU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_253__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

let impl_255__deserialize
      (#v_T #v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Deserialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
    : (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error) =
  let result:t_SecretTlsVecU32 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU32 v_T
  in
  let tmp0, out:(v_R & Core.Result.t_Result u32 Tls_codec.t_Error) =
    Tls_codec.f_tls_deserialize #u32 #FStar.Tactics.Typeclasses.solve #v_R bytes
  in
  let bytes:v_R = tmp0 in
  match out <: Core.Result.t_Result u32 Tls_codec.t_Error with
  | Core.Result.Result_Ok len ->
    let read:usize = Tls_codec.f_tls_serialized_len #u32 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU32 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Num.Error.t_TryFromIntError
                  (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU32 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU32 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (bytes, read, result <: (v_R & usize & t_SecretTlsVecU32 v_T))
          (fun temp_0_ ->
              let bytes, read, result:(v_R & usize & t_SecretTlsVecU32 v_T) = temp_0_ in
              let tmp0, out:(v_R & Core.Result.t_Result v_T Tls_codec.t_Error) =
                Tls_codec.f_tls_deserialize #v_T #FStar.Tactics.Typeclasses.solve #v_R bytes
              in
              let bytes:v_R = tmp0 in
              match out <: Core.Result.t_Result v_T Tls_codec.t_Error with
              | Core.Result.Result_Ok element ->
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU32 v_T = impl_260__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (bytes, read, result <: (v_R & usize & t_SecretTlsVecU32 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU32 v_T)))
                  (v_R & usize & t_SecretTlsVecU32 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (bytes,
                    (Core.Result.Result_Err err
                      <:
                      Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
                    <:
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error))
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
                    (Prims.unit & (v_R & usize & t_SecretTlsVecU32 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
                      (Prims.unit & (v_R & usize & t_SecretTlsVecU32 v_T)))
                  (v_R & usize & t_SecretTlsVecU32 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
          (v_R & usize & t_SecretTlsVecU32 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (bytes, read, result) ->
        let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error =
          Core.Result.Result_Ok result
          <:
          Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error
        in
        bytes, hax_temp_output
        <:
        (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    bytes,
    (Core.Result.Result_Err err <: Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
    <:
    (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_276
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_Deserialize v_T)
    : Tls_codec.t_Deserialize (t_SecretTlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_pre
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        ->
        true);
    f_tls_deserialize_post
    =
    (fun
        (#v_R: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
        (bytes: v_R)
        (out1: (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error))
        ->
        true);
    f_tls_deserialize
    =
    fun
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i4: Std.Io.t_Read v_R)
      (bytes: v_R)
      ->
      let tmp0, out:(v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error) =
        impl_255__deserialize #v_T #v_R bytes
      in
      let bytes:v_R = tmp0 in
      let hax_temp_output:Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error = out in
      bytes, hax_temp_output
      <:
      (v_R & Core.Result.t_Result (t_SecretTlsVecU32 v_T) Tls_codec.t_Error)
  }

let impl_256__deserialize_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_DeserializeBytes v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Zeroize.t_Zeroize v_T)
      (bytes: t_Slice u8)
    : Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error =
  let result:t_SecretTlsVecU32 v_T =
    { f_vec = Alloc.Vec.impl__new #v_T () } <: t_SecretTlsVecU32 v_T
  in
  match
    Tls_codec.f_tls_deserialize_bytes #u32 #FStar.Tactics.Typeclasses.solve bytes
    <:
    Core.Result.t_Result (u32 & t_Slice u8) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (len, remainder) ->
    let read:usize = Tls_codec.f_tls_serialized_len #u32 #FStar.Tactics.Typeclasses.solve len in
    let len_len:usize = read in
    (match
        Rust_primitives.Hax.while_loop_return (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU32 v_T) = temp_0_ in
              (read -! len_len <: usize) <.
              (Core.Result.impl__unwrap #usize
                  #Core.Num.Error.t_TryFromIntError
                  (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve len
                    <:
                    Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
                <:
                usize)
              <:
              bool)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU32 v_T) = temp_0_ in
              true)
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU32 v_T) = temp_0_ in
              Rust_primitives.Hax.Int.from_machine (mk_u32 0) <: Hax_lib.Int.t_Int)
          (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU32 v_T))
          (fun temp_0_ ->
              let read, remainder, result:(usize & t_Slice u8 & t_SecretTlsVecU32 v_T) = temp_0_ in
              match
                Tls_codec.f_tls_deserialize_bytes #v_T #FStar.Tactics.Typeclasses.solve remainder
                <:
                Core.Result.t_Result (v_T & t_Slice u8) Tls_codec.t_Error
              with
              | Core.Result.Result_Ok (element, next_remainder) ->
                let remainder:t_Slice u8 = next_remainder in
                let read:usize =
                  read +!
                  (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve element
                    <:
                    usize)
                in
                let result:t_SecretTlsVecU32 v_T = impl_260__push #v_T result element in
                Core.Ops.Control_flow.ControlFlow_Continue
                (read, remainder, result <: (usize & t_Slice u8 & t_SecretTlsVecU32 v_T))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU32 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU32 v_T)
              | Core.Result.Result_Err err ->
                Core.Ops.Control_flow.ControlFlow_Break
                (Core.Ops.Control_flow.ControlFlow_Break
                  (Core.Result.Result_Err err
                    <:
                    Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                  <:
                  Core.Ops.Control_flow.t_ControlFlow
                    (Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                    (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU32 v_T)))
                <:
                Core.Ops.Control_flow.t_ControlFlow
                  (Core.Ops.Control_flow.t_ControlFlow
                      (Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
                      (Prims.unit & (usize & t_Slice u8 & t_SecretTlsVecU32 v_T)))
                  (usize & t_Slice u8 & t_SecretTlsVecU32 v_T))
        <:
        Core.Ops.Control_flow.t_ControlFlow
          (Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
          (usize & t_Slice u8 & t_SecretTlsVecU32 v_T)
      with
      | Core.Ops.Control_flow.ControlFlow_Break ret -> ret
      | Core.Ops.Control_flow.ControlFlow_Continue (read, remainder, result) ->
        Core.Result.Result_Ok (result, remainder <: (t_SecretTlsVecU32 v_T & t_Slice u8))
        <:
        Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
  | Core.Result.Result_Err err ->
    Core.Result.Result_Err err
    <:
    Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_277
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i2: Tls_codec.t_DeserializeBytes v_T)
    : Tls_codec.t_DeserializeBytes (t_SecretTlsVecU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_deserialize_bytes_pre = (fun (bytes: t_Slice u8) -> true);
    f_tls_deserialize_bytes_post
    =
    (fun
        (bytes: t_Slice u8)
        (out: Core.Result.t_Result (t_SecretTlsVecU32 v_T & t_Slice u8) Tls_codec.t_Error)
        ->
        true);
    f_tls_deserialize_bytes = fun (bytes: t_Slice u8) -> impl_256__deserialize_bytes #v_T bytes
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_257 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Zeroize.t_Zeroize (t_SecretTlsVecU32 v_T) =
  {
    f_zeroize_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_zeroize_post = (fun (self: t_SecretTlsVecU32 v_T) (out: t_SecretTlsVecU32 v_T) -> true);
    f_zeroize
    =
    fun (self: t_SecretTlsVecU32 v_T) ->
      let self:t_SecretTlsVecU32 v_T =
        {
          self with
          f_vec
          =
          Zeroize.f_zeroize #(Alloc.Vec.t_Vec v_T Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            self.f_vec
        }
        <:
        t_SecretTlsVecU32 v_T
      in
      self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_258 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Zeroize.t_Zeroize v_T)
    : Core.Ops.Drop.t_Drop (t_SecretTlsVecU32 v_T) =
  {
    f_drop_pre = (fun (self: t_SecretTlsVecU32 v_T) -> true);
    f_drop_post = (fun (self: t_SecretTlsVecU32 v_T) (out: t_SecretTlsVecU32 v_T) -> true);
    f_drop
    =
    fun (self: t_SecretTlsVecU32 v_T) ->
      let self:t_SecretTlsVecU32 v_T =
        Zeroize.f_zeroize #(t_SecretTlsVecU32 v_T) #FStar.Tactics.Typeclasses.solve self
      in
      self
  }

type t_TlsByteSliceU8 = | TlsByteSliceU8 : t_Slice u8 -> t_TlsByteSliceU8

/// Get the raw slice.
let impl_278__as_slice (self: t_TlsByteSliceU8) : t_Slice u8 = self._0

let impl_279__assert_written_bytes (self: t_TlsByteSliceU8) (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_279__tls_serialized_byte_length (self: t_TlsByteSliceU8) : usize =
  (Core.Slice.impl__len #u8 (impl_278__as_slice self <: t_Slice u8) <: usize) +! mk_usize 1

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_282: Tls_codec.t_Size t_TlsByteSliceU8 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU8) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU8) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsByteSliceU8) -> impl_279__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_283: Tls_codec.t_Size t_TlsByteSliceU8 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU8) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU8) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsByteSliceU8) -> impl_279__tls_serialized_byte_length self
  }

let impl_279__get_content_lengths (self: t_TlsByteSliceU8)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteSliceU8 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 1 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u8__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_279__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU8)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_279__get_content_lengths self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u8
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u8
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u8 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
          <:
          u8)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_278__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist238 ->
            let written:usize = written +! hoist238 in
            (match
                impl_279__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_280: Tls_codec.t_Serialize t_TlsByteSliceU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_279__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_281: Tls_codec.t_Serialize t_TlsByteSliceU8 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU8)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU8)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU8)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_279__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsByteSliceU16 = | TlsByteSliceU16 : t_Slice u8 -> t_TlsByteSliceU16

/// Get the raw slice.
let impl_284__as_slice (self: t_TlsByteSliceU16) : t_Slice u8 = self._0

let impl_285__assert_written_bytes (self: t_TlsByteSliceU16) (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_285__tls_serialized_byte_length (self: t_TlsByteSliceU16) : usize =
  (Core.Slice.impl__len #u8 (impl_284__as_slice self <: t_Slice u8) <: usize) +! mk_usize 2

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_288: Tls_codec.t_Size t_TlsByteSliceU16 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU16) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU16) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU16) -> impl_285__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_289: Tls_codec.t_Size t_TlsByteSliceU16 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU16) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU16) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU16) -> impl_285__tls_serialized_byte_length self
  }

let impl_285__get_content_lengths (self: t_TlsByteSliceU16)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteSliceU16 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 2 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u16__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_285__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU16)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_285__get_content_lengths self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u16
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u16
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u16 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
          <:
          u16)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_284__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist244 ->
            let written:usize = written +! hoist244 in
            (match
                impl_285__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_286: Tls_codec.t_Serialize t_TlsByteSliceU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_285__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_287: Tls_codec.t_Serialize t_TlsByteSliceU16 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU16)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU16)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU16)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_285__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsByteSliceU24 = | TlsByteSliceU24 : t_Slice u8 -> t_TlsByteSliceU24

/// Get the raw slice.
let impl_290__as_slice (self: t_TlsByteSliceU24) : t_Slice u8 = self._0

let impl_291__assert_written_bytes (self: t_TlsByteSliceU24) (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_291__tls_serialized_byte_length (self: t_TlsByteSliceU24) : usize =
  (Core.Slice.impl__len #u8 (impl_290__as_slice self <: t_Slice u8) <: usize) +! mk_usize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_294: Tls_codec.t_Size t_TlsByteSliceU24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU24) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU24) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU24) -> impl_291__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_295: Tls_codec.t_Size t_TlsByteSliceU24 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU24) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU24) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU24) -> impl_291__tls_serialized_byte_length self
  }

let impl_291__get_content_lengths (self: t_TlsByteSliceU24)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteSliceU24 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 3 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #Tls_codec.t_U24
          #usize
          #FStar.Tactics.Typeclasses.solve
          Tls_codec.impl_U24__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_291__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU24)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_291__get_content_lengths self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #Tls_codec.t_U24
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #Tls_codec.t_U24
            #Tls_codec.t_Error
            (Core.Convert.f_try_from #Tls_codec.t_U24
                #usize
                #FStar.Tactics.Typeclasses.solve
                byte_length
              <:
              Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
          <:
          Tls_codec.t_U24)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_290__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist250 ->
            let written:usize = written +! hoist250 in
            (match
                impl_291__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_292: Tls_codec.t_Serialize t_TlsByteSliceU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_291__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_293: Tls_codec.t_Serialize t_TlsByteSliceU24 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU24)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU24)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU24)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_291__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsByteSliceU32 = | TlsByteSliceU32 : t_Slice u8 -> t_TlsByteSliceU32

/// Get the raw slice.
let impl_296__as_slice (self: t_TlsByteSliceU32) : t_Slice u8 = self._0

let impl_297__assert_written_bytes (self: t_TlsByteSliceU32) (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

/// The serialized len
let impl_297__tls_serialized_byte_length (self: t_TlsByteSliceU32) : usize =
  (Core.Slice.impl__len #u8 (impl_296__as_slice self <: t_Slice u8) <: usize) +! mk_usize 4

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_300: Tls_codec.t_Size t_TlsByteSliceU32 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU32) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU32) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU32) -> impl_297__tls_serialized_byte_length self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_301: Tls_codec.t_Size t_TlsByteSliceU32 =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsByteSliceU32) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsByteSliceU32) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsByteSliceU32) -> impl_297__tls_serialized_byte_length self
  }

let impl_297__get_content_lengths (self: t_TlsByteSliceU32)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #t_TlsByteSliceU32 #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 4 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Num.Error.t_TryFromIntError
      (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u32__MAX
        <:
        Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_297__serialize_bytes
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU32)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_297__get_content_lengths self <: Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u32
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u32
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u32 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
          <:
          u32)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        let tmp0, out:(v_W & Core.Result.t_Result usize Std.Io.Error.t_Error) =
          Std.Io.f_write #v_W
            #FStar.Tactics.Typeclasses.solve
            writer
            (impl_296__as_slice self <: t_Slice u8)
        in
        let writer:v_W = tmp0 in
        (match out <: Core.Result.t_Result usize Std.Io.Error.t_Error with
          | Core.Result.Result_Ok hoist256 ->
            let written:usize = written +! hoist256 in
            (match
                impl_297__assert_written_bytes self tls_serialized_len written
                <:
                Core.Result.t_Result Prims.unit Tls_codec.t_Error
              with
              | Core.Result.Result_Ok _ ->
                let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                  Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
                in
                writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
              | Core.Result.Result_Err err ->
                writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
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
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_298: Tls_codec.t_Serialize t_TlsByteSliceU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_297__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_299: Tls_codec.t_Serialize t_TlsByteSliceU32 =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU32)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
        (self: t_TlsByteSliceU32)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Std.Io.t_Write v_W)
      (self: t_TlsByteSliceU32)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_297__serialize_bytes #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsSliceU8 (v_T: Type0) = | TlsSliceU8 : t_Slice v_T -> t_TlsSliceU8 v_T

/// Get the raw slice.
let impl_302__as_slice (#v_T: Type0) (self: t_TlsSliceU8 v_T) : t_Slice v_T = self._0

/// The serialized len
let impl_303__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsSliceU8 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_302__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 1)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

let impl_304__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU8 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_307 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU8 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsSliceU8 v_T) -> impl_303__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_308 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU8 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU8 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU8 v_T) (out: usize) -> true);
    f_tls_serialized_len = fun (self: t_TlsSliceU8 v_T) -> impl_303__tls_serialized_length #v_T self
  }

let impl_304__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU8 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsSliceU8 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 1 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u8 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u8__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_304__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU8 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_304__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u8
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u8
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u8 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u8 Core.Num.Error.t_TryFromIntError)
          <:
          u8)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_302__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist262 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist262 <: (v_W & usize))
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
            match
              impl_304__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_305 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_304__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_306 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU8 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU8 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU8 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU8 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_304__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsSliceU16 (v_T: Type0) = | TlsSliceU16 : t_Slice v_T -> t_TlsSliceU16 v_T

/// Get the raw slice.
let impl_309__as_slice (#v_T: Type0) (self: t_TlsSliceU16 v_T) : t_Slice v_T = self._0

/// The serialized len
let impl_310__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsSliceU16 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_309__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 2)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

let impl_311__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU16 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_314 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU16 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU16 v_T) -> impl_310__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_315 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU16 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU16 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU16 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU16 v_T) -> impl_310__tls_serialized_length #v_T self
  }

let impl_311__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU16 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsSliceU16 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 2 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #u16 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u16__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_311__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU16 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_311__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u16
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u16
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u16 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u16 Core.Num.Error.t_TryFromIntError)
          <:
          u16)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_309__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist268 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist268 <: (v_W & usize))
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
            match
              impl_311__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_312 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_311__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_313 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU16 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU16 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU16 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU16 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_311__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsSliceU24 (v_T: Type0) = | TlsSliceU24 : t_Slice v_T -> t_TlsSliceU24 v_T

/// Get the raw slice.
let impl_316__as_slice (#v_T: Type0) (self: t_TlsSliceU24 v_T) : t_Slice v_T = self._0

/// The serialized len
let impl_317__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsSliceU24 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_316__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 3)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

let impl_318__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU24 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_321 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU24 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU24 v_T) -> impl_317__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_322 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU24 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU24 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU24 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU24 v_T) -> impl_317__tls_serialized_length #v_T self
  }

let impl_318__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU24 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsSliceU24 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 3 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Convert.t_Infallible
      (Core.Convert.f_try_into #Tls_codec.t_U24
          #usize
          #FStar.Tactics.Typeclasses.solve
          Tls_codec.impl_U24__MAX
        <:
        Core.Result.t_Result usize Core.Convert.t_Infallible)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_318__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU24 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_318__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #Tls_codec.t_U24
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #Tls_codec.t_U24
            #Tls_codec.t_Error
            (Core.Convert.f_try_from #Tls_codec.t_U24
                #usize
                #FStar.Tactics.Typeclasses.solve
                byte_length
              <:
              Core.Result.t_Result Tls_codec.t_U24 Tls_codec.t_Error)
          <:
          Tls_codec.t_U24)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_316__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist274 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist274 <: (v_W & usize))
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
            match
              impl_318__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_319 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_318__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_320 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU24 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU24 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU24 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU24 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_318__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

type t_TlsSliceU32 (v_T: Type0) = | TlsSliceU32 : t_Slice v_T -> t_TlsSliceU32 v_T

/// Get the raw slice.
let impl_323__as_slice (#v_T: Type0) (self: t_TlsSliceU32 v_T) : t_Slice v_T = self._0

/// The serialized len
let impl_324__tls_serialized_length
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
      (self: t_TlsSliceU32 v_T)
    : usize =
  Core.Iter.Traits.Iterator.f_fold #(Core.Slice.Iter.t_Iter v_T)
    #FStar.Tactics.Typeclasses.solve
    #usize
    (Core.Slice.impl__iter #v_T (impl_323__as_slice #v_T self <: t_Slice v_T)
      <:
      Core.Slice.Iter.t_Iter v_T)
    (mk_usize 4)
    (fun acc e ->
        let acc:usize = acc in
        let e:v_T = e in
        acc +! (Tls_codec.f_tls_serialized_len #v_T #FStar.Tactics.Typeclasses.solve e <: usize)
        <:
        usize)

let impl_325__assert_written_bytes
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU32 v_T)
      (tls_serialized_len written: usize)
    : Core.Result.t_Result Prims.unit Tls_codec.t_Error =
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        match written, tls_serialized_len <: (usize & usize) with
        | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
      in
      ()
  in
  if written <>. tls_serialized_len
  then
    Core.Result.Result_Err
    (Tls_codec.Error_EncodingError
      (Core.Hint.must_use #Alloc.String.t_String
          (Alloc.Fmt.format (Core.Fmt.Rt.impl_2__new_v1 (mk_usize 3)
                  (mk_usize 2)
                  (let list = [""; " bytes should have been serialized but "; " were written"] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 3);
                    Rust_primitives.Hax.array_of_list 3 list)
                  (let list =
                      [
                        Core.Fmt.Rt.impl__new_display #usize tls_serialized_len
                        <:
                        Core.Fmt.Rt.t_Argument;
                        Core.Fmt.Rt.impl__new_display #usize written <: Core.Fmt.Rt.t_Argument
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
    Core.Result.t_Result Prims.unit Tls_codec.t_Error
  else Core.Result.Result_Ok (() <: Prims.unit) <: Core.Result.t_Result Prims.unit Tls_codec.t_Error

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_328 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU32 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU32 v_T) -> impl_324__tls_serialized_length #v_T self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_329 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Size v_T)
    : Tls_codec.t_Size (t_TlsSliceU32 v_T) =
  {
    f_tls_serialized_len_pre = (fun (self: t_TlsSliceU32 v_T) -> true);
    f_tls_serialized_len_post = (fun (self: t_TlsSliceU32 v_T) (out: usize) -> true);
    f_tls_serialized_len
    =
    fun (self: t_TlsSliceU32 v_T) -> impl_324__tls_serialized_length #v_T self
  }

let impl_325__get_content_lengths
      (#v_T: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (self: t_TlsSliceU32 v_T)
    : Core.Result.t_Result (usize & usize) Tls_codec.t_Error =
  let tls_serialized_len:usize =
    Tls_codec.f_tls_serialized_len #(t_TlsSliceU32 v_T) #FStar.Tactics.Typeclasses.solve self
  in
  let byte_length:usize = tls_serialized_len -! mk_usize 4 in
  let max_len:usize =
    Core.Result.impl__unwrap #usize
      #Core.Num.Error.t_TryFromIntError
      (Core.Convert.f_try_into #u32 #usize #FStar.Tactics.Typeclasses.solve Core.Num.impl_u32__MAX
        <:
        Core.Result.t_Result usize Core.Num.Error.t_TryFromIntError)
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(byte_length <=. max_len <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core.Panicking.panic_fmt (Core.Fmt.Rt.impl_2__new_v1 (mk_usize
                      2)
                    (mk_usize 2)
                    (let list =
                        ["Vector length can't be encoded in the vector length a "; " >= "]
                      in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 2);
                      Rust_primitives.Hax.array_of_list 2 list)
                    (let list =
                        [
                          Core.Fmt.Rt.impl__new_display #usize byte_length <: Core.Fmt.Rt.t_Argument;
                          Core.Fmt.Rt.impl__new_display #usize max_len <: Core.Fmt.Rt.t_Argument
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
  if byte_length >. max_len
  then
    Core.Result.Result_Err (Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error)
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  else
    Core.Result.Result_Ok (tls_serialized_len, byte_length <: (usize & usize))
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error

let impl_325__serialize
      (#v_T #v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU32 v_T)
      (writer: v_W)
    : (v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
  match
    impl_325__get_content_lengths #v_T self
    <:
    Core.Result.t_Result (usize & usize) Tls_codec.t_Error
  with
  | Core.Result.Result_Ok (tls_serialized_len, byte_length) ->
    let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
      Tls_codec.f_tls_serialize #u32
        #FStar.Tactics.Typeclasses.solve
        #v_W
        (Core.Result.impl__unwrap #u32
            #Core.Num.Error.t_TryFromIntError
            (Core.Convert.f_try_from #u32 #usize #FStar.Tactics.Typeclasses.solve byte_length
              <:
              Core.Result.t_Result u32 Core.Num.Error.t_TryFromIntError)
          <:
          u32)
        writer
    in
    let writer:v_W = tmp0 in
    (match out <: Core.Result.t_Result usize Tls_codec.t_Error with
      | Core.Result.Result_Ok written ->
        (match
            Rust_primitives.Hax.Folds.fold_return (Core.Iter.Traits.Collect.f_into_iter #(Core.Slice.Iter.t_Iter
                    v_T)
                  #FStar.Tactics.Typeclasses.solve
                  (Core.Slice.impl__iter #v_T (impl_323__as_slice #v_T self <: t_Slice v_T)
                    <:
                    Core.Slice.Iter.t_Iter v_T)
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
                  | Core.Result.Result_Ok hoist280 ->
                    Core.Ops.Control_flow.ControlFlow_Continue
                    (writer, written +! hoist280 <: (v_W & usize))
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
            match
              impl_325__assert_written_bytes #v_T self tls_serialized_len written
              <:
              Core.Result.t_Result Prims.unit Tls_codec.t_Error
            with
            | Core.Result.Result_Ok _ ->
              let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error =
                Core.Result.Result_Ok written <: Core.Result.t_Result usize Tls_codec.t_Error
              in
              writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
            | Core.Result.Result_Err err ->
              writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
              <:
              (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
      | Core.Result.Result_Err err ->
        writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
        <:
        (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
  | Core.Result.Result_Err err ->
    writer, (Core.Result.Result_Err err <: Core.Result.t_Result usize Tls_codec.t_Error)
    <:
    (v_W & Core.Result.t_Result usize Tls_codec.t_Error)

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_326 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_325__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_327 (#v_T: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Tls_codec.t_Serialize v_T)
    : Tls_codec.t_Serialize (t_TlsSliceU32 v_T) =
  {
    _super_6186925850915422136 = FStar.Tactics.Typeclasses.solve;
    f_tls_serialize_pre
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU32 v_T)
        (writer: v_W)
        ->
        true);
    f_tls_serialize_post
    =
    (fun
        (#v_W: Type0)
        (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
        (self: t_TlsSliceU32 v_T)
        (writer: v_W)
        (out1: (v_W & Core.Result.t_Result usize Tls_codec.t_Error))
        ->
        true);
    f_tls_serialize
    =
    fun
      (#v_W: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i3: Std.Io.t_Write v_W)
      (self: t_TlsSliceU32 v_T)
      (writer: v_W)
      ->
      let tmp0, out:(v_W & Core.Result.t_Result usize Tls_codec.t_Error) =
        impl_325__serialize #v_T #v_W self writer
      in
      let writer:v_W = tmp0 in
      let hax_temp_output:Core.Result.t_Result usize Tls_codec.t_Error = out in
      writer, hax_temp_output <: (v_W & Core.Result.t_Result usize Tls_codec.t_Error)
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core.Convert.t_From Tls_codec.t_Error Core.Num.Error.t_TryFromIntError =
  {
    f_from_pre = (fun (e_e: Core.Num.Error.t_TryFromIntError) -> true);
    f_from_post = (fun (e_e: Core.Num.Error.t_TryFromIntError) (out: Tls_codec.t_Error) -> true);
    f_from
    =
    fun (e_e: Core.Num.Error.t_TryFromIntError) ->
      Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Core.Convert.t_From Tls_codec.t_Error Core.Convert.t_Infallible =
  {
    f_from_pre = (fun (e_e: Core.Convert.t_Infallible) -> true);
    f_from_post = (fun (e_e: Core.Convert.t_Infallible) (out: Tls_codec.t_Error) -> true);
    f_from
    =
    fun (e_e: Core.Convert.t_Infallible) -> Tls_codec.Error_InvalidVectorLength <: Tls_codec.t_Error
  }
