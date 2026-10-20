//! Fuzz target `profile` of [`vilicus_fuzz::TARGETS`].

#![cfg_attr(feature = "libfuzzer", no_main)]

vilicus_fuzz::fuzz_target!();
