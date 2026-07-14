import { Q_Asset, Quorum } from "quantova/primitives";
contract Custody {
  state {
    guardians: GuardianSet<7>;
    vault: Q_Asset<QTOV>;
    frozen: u8 = 0;
  }
  genesis {
    guardians = deploy_params.guardians;
  }
  entry disburse(order: Disbursement, approvals: Quorum<5 of 7, guardians>)
    conserves QTOV
    writes(vault)
    denies frozen == 1
  {
    guard vault.amount >= order.amount;
    let out = vault.split(order.amount);
    send(order.to, out);
    emit Disbursed(order.to, order.amount, approvals.digest);
  }
  entry freeze(order: FreezeOrder, approvals: Quorum<3 of 7, guardians>)
    writes(frozen)
  {
    frozen = 1;
    emit Frozen(approvals.digest);
  }
  entry unfreeze(order: UnfreezeOrder, approvals: Quorum<5 of 7, guardians>)
    writes(frozen)
    after 12 hours from approvals.first
  {
    frozen = 0;
    emit Unfrozen(approvals.digest);
  }
  event Disbursed(to: Q_Address, amount: u128, digest: Q_Hash);
  event Frozen(digest: Q_Hash);
  event Unfrozen(digest: Q_Hash);
}
