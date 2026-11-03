import { Q_Asset, Quorum } from "quantova/primitives";
contract MultiSig {
  state {
    signers: GuardianSet<5>;
    threshold: u8 = 3;
    vault: Q_Asset<QTOV>;
    rotation_armed: u64;
  }
  genesis {
    signers = deploy_params.signers;
  }
  entry execute(payment: Payment, approvals: Quorum<3 of 5, signers>)
    writes(vault)
    conserves QTOV
    reads(signers)
  {
    guard payment.amount <= vault.amount;
    let out = vault.split(payment.amount);
    send(payment.to, out);
    emit Executed(payment.to, payment.amount, approvals.signer_bits);
  }
  entry arm_rotation(approvals: Quorum<4 of 5, signers>)
    writes(rotation_armed)
  {
    rotation_armed = now;
    emit RotationArmed(approvals.signer_bits);
  }
  entry rotate(new_signers: GuardianSet<5>, approvals: Quorum<4 of 5, signers>)
    writes(signers, rotation_armed)
    after 24 hours from rotation_armed
    denies rotation_armed == 0
  {
    signers = new_signers;
    rotation_armed = 0;
    emit Rotated(approvals.signer_bits);
  }
  event Executed(to: Q_Address, amount: u128, signer_bits: Q_Word64);
  event RotationArmed(signer_bits: Q_Word64);
  event Rotated(signer_bits: Q_Word64);
}
