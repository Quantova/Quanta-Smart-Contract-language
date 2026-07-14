import { Q_Asset } from "quantova/primitives";
contract Vesting {
  state {
    beneficiary: Q_Address;
    locked: Q_Asset<QTOV>;
    start: Time = 2026-01-01;
    total: u128;
    claimed: u128;
  }
  genesis {
    beneficiary = deploy_params.beneficiary;
    total = deploy_params.total;
  }
  invariant claimed <= total;
  entry claim(order: ClaimOrder signed by beneficiary)
    conserves QTOV
    writes(claimed, locked)
    after 365 days from start
    limits order.amount <= total - claimed
  {
    claimed += order.amount;
    let out = locked.split(order.amount);
    send(beneficiary, out);
    emit Claimed(beneficiary, order.amount);
  }
  event Claimed(to: Q_Address, amount: u128);
}
