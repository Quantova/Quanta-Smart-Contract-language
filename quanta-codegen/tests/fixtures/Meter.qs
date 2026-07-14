contract Meter {
  state {
    reading: u64;
  }
  entry advance(step: u64)
    writes(reading)
  {
    guard step > 0;
    reading = checked(reading + step);
    emit Advanced(reading);
  }
  event Advanced(value: u64);
}
