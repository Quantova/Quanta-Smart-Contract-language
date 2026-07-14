contract TreasuryBond {
  asset BOND_2036;
  state {
    registrar: Q_Address;
    holders: Registry<Q_Address>;
    maturity: Time = 2036-07-01;
    coupon_bps: u16 = 425;
  }
  entry subscribe(order: SubscriptionOrder signed by registrar,
                  payment: sealed Q_Asset<QSGD>)
    conserves QSGD
    mints BOND_2036
    denies !holders.contains(order.investor)
  {
    treasury.merge(payment);
    send(order.investor, mint(order.units));
    emit Subscribed(order.investor, order.units);
  }
  entry redeem(units: Q_Asset<BOND_2036>)
    burns BOND_2036
    conserves QSGD
    after maturity
  {
    guard treasury.amount >= units.amount * face_value;
    let principal = treasury.split(units.amount * face_value);
    send(caller, principal);
    emit Redeemed(caller, units.amount);
  }
}
