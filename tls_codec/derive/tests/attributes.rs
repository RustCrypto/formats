#[test]
fn attributes() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/attributes/*.rs");
    #[cfg(feature = "conditional_deserialization")]
    t.compile_fail("tests/conditional_deserialization_attributes/*.rs");
}
