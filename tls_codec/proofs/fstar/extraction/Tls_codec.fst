module Tls_codec
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

let t_Error = Tls_codec.Bundle.t_Error
include Tls_codec.Bundle {t_Size as t_Size}
include Tls_codec.Bundle {t_Serialize as t_Serialize}
include Tls_codec.Bundle {t_SerializeBytes as t_SerializeBytes}
include Tls_codec.Bundle {t_Deserialize as t_Deserialize}
include Tls_codec.Bundle {t_DeserializeBytes as t_DeserializeBytes}

include Tls_codec.Bundle {Error_EncodingError as Error_EncodingError}

include Tls_codec.Bundle {Error_InvalidVectorLength as Error_InvalidVectorLength}

include Tls_codec.Bundle {Error_InvalidWriteLength as Error_InvalidWriteLength}

include Tls_codec.Bundle {Error_InvalidInput as Error_InvalidInput}

include Tls_codec.Bundle {Error_DecodingError as Error_DecodingError}

include Tls_codec.Bundle {Error_EndOfStream as Error_EndOfStream}

include Tls_codec.Bundle {Error_TrailingData as Error_TrailingData}

include Tls_codec.Bundle {Error_UnknownValue as Error_UnknownValue}

include Tls_codec.Bundle {Error_LibraryError as Error_LibraryError}

include Tls_codec.Bundle {impl_9 as impl_9}

include Tls_codec.Bundle {impl_10 as impl_10}

include Tls_codec.Bundle {impl_11 as impl_11}

include Tls_codec.Bundle {impl_12 as impl_12}

include Tls_codec.Bundle {impl_13 as impl_13}

include Tls_codec.Bundle {impl as impl}

include Tls_codec.Bundle {impl_1 as impl_1}

include Tls_codec.Bundle {impl_2 as impl_2}

include Tls_codec.Bundle {f_tls_serialized_len_pre as f_tls_serialized_len_pre}

include Tls_codec.Bundle {f_tls_serialized_len_post as f_tls_serialized_len_post}

include Tls_codec.Bundle {f_tls_serialized_len as f_tls_serialized_len}

include Tls_codec.Bundle {f_tls_serialize_pre as f_tls_serialize_pre}

include Tls_codec.Bundle {f_tls_serialize_post as f_tls_serialize_post}

include Tls_codec.Bundle {f_tls_serialize as f_tls_serialize}

include Tls_codec.Bundle {f_tls_serialize_detached_pre as f_tls_serialize_detached_pre}

include Tls_codec.Bundle {f_tls_serialize_detached_post as f_tls_serialize_detached_post}

include Tls_codec.Bundle {f_tls_serialize_detached as f_tls_serialize_detached}

include Tls_codec.Bundle {impl_3 as impl_3}

include Tls_codec.Bundle {f_tls_serialize_bytes_pre as f_tls_serialize_bytes_pre}

include Tls_codec.Bundle {f_tls_serialize_bytes_post as f_tls_serialize_bytes_post}

include Tls_codec.Bundle {f_tls_serialize_bytes as f_tls_serialize_bytes}

include Tls_codec.Bundle {f_tls_deserialize_pre as f_tls_deserialize_pre}

include Tls_codec.Bundle {f_tls_deserialize_post as f_tls_deserialize_post}

include Tls_codec.Bundle {f_tls_deserialize as f_tls_deserialize}

include Tls_codec.Bundle {f_tls_deserialize_exact_pre as f_tls_deserialize_exact_pre}

include Tls_codec.Bundle {f_tls_deserialize_exact_post as f_tls_deserialize_exact_post}

include Tls_codec.Bundle {f_tls_deserialize_exact as f_tls_deserialize_exact}

include Tls_codec.Bundle {impl_4 as impl_4}

include Tls_codec.Bundle {f_tls_deserialize_bytes_pre as f_tls_deserialize_bytes_pre}

include Tls_codec.Bundle {f_tls_deserialize_bytes_post as f_tls_deserialize_bytes_post}

include Tls_codec.Bundle {f_tls_deserialize_bytes as f_tls_deserialize_bytes}

include Tls_codec.Bundle {f_tls_deserialize_exact_bytes_pre as f_tls_deserialize_exact_bytes_pre}

include Tls_codec.Bundle {f_tls_deserialize_exact_bytes_post as f_tls_deserialize_exact_bytes_post}

include Tls_codec.Bundle {f_tls_deserialize_exact_bytes as f_tls_deserialize_exact_bytes}

include Tls_codec.Bundle {impl_5 as impl_5}

include Tls_codec.Bundle {t_U24 as t_U24}

include Tls_codec.Bundle {U24 as U24}

include Tls_codec.Bundle {impl_14 as impl_14}

include Tls_codec.Bundle {impl_15 as impl_15}

include Tls_codec.Bundle {impl_16 as impl_16}

include Tls_codec.Bundle {impl_17 as impl_17}

include Tls_codec.Bundle {impl_18 as impl_18}

include Tls_codec.Bundle {impl_19 as impl_19}

include Tls_codec.Bundle {impl_6__MAX as impl_U24__MAX}

include Tls_codec.Bundle {impl_6__MIN as impl_U24__MIN}

include Tls_codec.Bundle {impl_6__from_be_bytes as impl_U24__from_be_bytes}

include Tls_codec.Bundle {impl_6__to_be_bytes as impl_U24__to_be_bytes}

include Tls_codec.Bundle {impl_7 as impl_7}

include Tls_codec.Bundle {f_from__impl_7__v_LEN as f_from__impl_7__v_LEN}

include Tls_codec.Bundle {impl_8 as impl_8}

include Tls_codec.Bundle {f_try_from__impl_8__v_LEN as f_try_from__impl_8__v_LEN}

include Tls_codec.Bundle {deserialize_primitives as deserialize_primitives}
