# Fuzzeval

Docker configurations and setup for large-scale fuzzing for evaluation of fuzzing systems
as described in Klees et. al "Evaluating Fuzz Testing" (given in
[docs](docs/evaluating_fuzz_testing.pdf)).

## IMPORTANT! System Configuration:

```sh
echo core | sudo tee /proc/sys/kernel/core_pattern
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Corpus

The corpus is composed of the CGC dataset and the LAVA-M dataset, and the corpus
should be built directly from the [corpus directory](corpus) as follows.

[`corpus/src`](corpus/src) should contain one subdirectory per input dataset. Each of
these subdirectories should contain a `build.sh` script that will build each binary
in the dataset and copy the set of build artifacts (the binary and any dependencies) to
[`corpus/build/the_dataset_name/the_testcase_name/`](corpus/build).

The `build.sh` script should also generate a directory 
`corpus/build/the_dataset_name/the_testcase_name/seeds/` with a subdirectory for each
seed set, so if you want to test it with a given set of seeds and with the empty seed,
you should have two directories called `good` and `empty` (for example).

## Fuzzers

Fuzzeval provides builds of `AFL++`, `SymQEMU`, and `T-Fuzz` for a thorough comparison
of fuzzing improvement techniques against the current state of the art for symbolic
analysis-assisted fuzzing.

## Evaluation Strategy

For Reface, we specifically evaluate the following seed input methods for each
fuzzer for each binary:

* Good seed - a valid or invalid program input set that conforms to the expected input for
  that program, minimized with `optimin`, as recommended by Herrera et. al.
* Empty Seed - Empty seed file

## Fuzzer Settings

## Evaluation Metrics

As suggested in Klees et. al, we evaluate against programs with known sets of bugs in
order to evaluate on the metric of "number of bugs found" as a primary metric.

As per Herrera et. al, we also consider Bug Survival time, when fuzzing without refacing
discovers the same bugs as fuzzing with refacing, how quickly were the same bugs discovered?

We use coverage as a secondary metric, as this is particularly relevant for our system.


## Handling failures

We evaluate over a large set of binaries, and therefore are not able to debug specific
failures in depth.

## Notes

* Unintended CGC bugs: https://github.com/mfthomps/CGC-Analysis
* AFLplusplus can be run with the wrapper with the given configuration with:
  `python3 /scripts/aflplusplus_wrapper.py -t 1440 -a $(pwd)/afl-fuzz -s /corpus/test_fuzzers_work/AIS-Lite/seeds/ -o /output /corpus/test_fuzzers_work/AIS-Lite/AIS-Lite`