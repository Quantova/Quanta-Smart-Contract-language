contract TreasuryBond {
  asset BOND_2036;
  state {
    registrar: Q_Address;
    holders: Registry<Q_Address>;
    treasury: Q_Asset<QSGD>;
    face_value: u64 = 1_000;
    maturity: Time = 2036-07-01;
    coupon_bps: u16 = 425;
  }
  genesis {
    registrar = deployer;
  }
  entry enroll(order: EnrollOrder signed by registrar)
    writes(holders)
    denies holders.contains(order.investor)
  {
    holders.insert(order.investor);
    emit Enrolled(order.investor);
  }
  entry subscribe(order: SubscriptionOrder signed by registrar,
                  payment: sealed Q_Asset<QSGD>)
    conserves QSGD
    mints BOND_2036
    writes(treasury)
    denies !holders.contains(order.investor)
  {
    guard payment.amount >= order.units * face_value;
    treasury.merge(payment);
    send(order.investor, mint(order.units));
    emit Subscribed(order.investor, order.units);
  }
  entry redeem(units: Q_Asset<BOND_2036>)
    burns BOND_2036
    conserves QSGD
    writes(treasury)
    after maturity
  {
    guard treasury.amount >= units.amount * face_value;
    let principal = treasury.split(units.amount * face_value);
    send(caller, principal);
    emit Redeemed(caller, units.amount);
  }
  event Enrolled(investor: Q_Address);
  event Subscribed(investor: Q_Address, units: u128);
  event Redeemed(holder: Q_Address, units: u128);
}
