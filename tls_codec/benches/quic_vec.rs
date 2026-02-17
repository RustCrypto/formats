use criterion::{BatchSize, Criterion};
use criterion::{criterion_group, criterion_main};

use tls_codec::*;

/// Length of the test bytes vector.
const N: usize = 0xFFFF;

fn vector(c: &mut Criterion) {
    c.bench_function("TLS Serialize VL Vector", |b| {
        b.iter_batched_ref(
            || (vec![77u8; N], Vec::with_capacity(8 + N)),
            |(long_vec, buf)| Serialize::tls_serialize(long_vec, buf).unwrap(),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("TLS Deserialize VL Vector", |b| {
        b.iter_batched_ref(
            || {
                let long_vec = vec![77u8; N];
                long_vec.tls_serialize_detached().unwrap()
            },
            |serialized_long_vec| {
                Vec::<u8>::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn byte_vector(c: &mut Criterion) {
    c.bench_function("TLS Serialize VL Byte Vector", |b| {
        b.iter_batched_ref(
            || (VLBytes::new(vec![77u8; N]), Vec::with_capacity(8 + N)),
            |(long_vec, buf)| Serialize::tls_serialize(long_vec, buf).unwrap(),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("TLS Deserialize VL Byte Vector", |b| {
        b.iter_batched_ref(
            || {
                let long_vec = vec![77u8; N];
                VLByteSlice(&long_vec).tls_serialize_detached().unwrap()
            },
            |serialized_long_vec| {
                VLBytes::tls_deserialize(&mut serialized_long_vec.as_slice()).unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn byte_slice(c: &mut Criterion) {
    c.bench_function("TLS Serialize VL Byte Slice", |b| {
        b.iter_batched_ref(
            || (vec![77u8; N], Vec::with_capacity(8 + N)),
            |(long_vec, buf)| VLByteSlice(long_vec).tls_serialize(buf).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn slice(c: &mut Criterion) {
    c.bench_function("TLS Serialize VL Slice", |b| {
        b.iter_batched_ref(
            || (vec![77u8; N], Vec::with_capacity(8 + N)),
            |(long_vec, buf)| Serialize::tls_serialize(&long_vec.as_slice(), buf).unwrap(),
            BatchSize::SmallInput,
        )
    });
}
fn benchmark(c: &mut Criterion) {
    vector(c);
    slice(c);
    byte_vector(c);
    byte_slice(c);
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
