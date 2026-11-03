import { Q_Asset, Quorum } from "quantova/primitives";
contract Custody {
  state {
    guardians: GuardianSet<7>;
    vault: Q_Asset<QTOV>;
    frozen: u8 = 0;
    unfreeze_armed: u64;
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
    emit Disbursed(order.to, order.amount, approvals.signer_bits);
  }
  entry freeze(order: FreezeOrder, approvals: Quorum<3 of 7, guardians>)
    writes(frozen, unfreeze_armed)
  {
    frozen = 1;
    unfreeze_armed = 0;
    emit Frozen(approvals.signer_bits);
  }
  entry arm_unfreeze(approvals: Quorum<5 of 7, guardians>)
    writes(unfreeze_armed)
  {
    unfreeze_armed = now;
    emit UnfreezeArmed(approvals.signer_bits);
  }
  entry unfreeze(approvals: Quorum<5 of 7, guardians>)
    writes(frozen, unfreeze_armed)
    after 12 hours from unfreeze_armed
    denies unfreeze_armed == 0
  {
    frozen = 0;
    unfreeze_armed = 0;
    emit Unfrozen(approvals.signer_bits);
  }
  event Disbursed(to: Q_Address, amount: u128, signer_bits: Q_Word64);
  event Frozen(signer_bits: Q_Word64);
  event UnfreezeArmed(signer_bits: Q_Word64);
  event Unfrozen(signer_bits: Q_Word64);
}
