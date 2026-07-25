#![no_main]

use hns_conformance::exercise_production_parsers;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    if let Ok(accepted) = exercise_production_parsers(input) {
        std::hint::black_box(accepted.bits());
    }
});
