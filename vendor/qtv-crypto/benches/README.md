# Benchmarks

This benchmark measures the throughput of each primitive in the crate. The numbers feed two consumers. They calibrate the gas schedule for the native post quantum opcodes in the virtual machine and they set the validator resource budget that the benchmarks repository enforces as a consensus parameter.

The hashing primitive sha3_256 processes a one kilobyte input in about 3.8 microseconds per call. Key generation for ml_dsa takes about 96 microseconds per call, signing takes about 195 microseconds per call, and verification takes about 96 microseconds per call. For ml_kem key generation takes about 28 microseconds per call, encapsulation takes about 30 microseconds per call, and decapsulation takes about 33 microseconds per call. The stateless hash based scheme slh_dsa is far heavier, with key generation near 124 milliseconds per call, signing near 1.2 seconds per call, and verification near 0.98 milliseconds per call. The verifiable random function builds on that same scheme, so proving takes about 1.4 seconds per call while verification takes about 0.96 milliseconds per call.

These figures come from a release build measured with cargo bench and the exact printed output lives in results.txt.
