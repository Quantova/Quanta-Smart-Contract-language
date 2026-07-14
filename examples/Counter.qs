contract Counter {
  state {
    owner: Q_Address;
    count: u64;
  }
  genesis {
    owner = deployer;
    count = 0;
  }
  entry bump(order: BumpOrder signed by owner)
    writes(count)
  {
    count = checked(count + order.step);
    emit Bumped(count);
  }
  event Bumped(value: u64);
}
