import { Q_Asset, Quorum } from "quantova/primitives";
contract MultiSig {
  state {
    signers: GuardianSet<5>;
    threshold: u8 = 3;
    nonce: u64;
    vault: Q_Asset<QTOV>;
  }
  genesis {
    signers = deploy_params.signers;
  }
  entry execute(payment: Payment, approvals: Quorum<3 of 5, signers>)
    writes(nonce, vault)
    conserves QTOV
    reads(signers)
  {
    guard payment.amount <= vault.amount;
    nonce += 1;
    let out = vault.split(payment.amount);
    send(payment.to, out);
    emit Executed(payment.to, payment.amount, approvals.digest);
  }
  entry rotate(new_signers: GuardianSet<5>, approvals: Quorum<4 of 5, signers>)
    writes(signers)
    after 24 hours from approvals.first
  {
    signers = new_signers;
    emit Rotated(approvals.digest);
  }
  event Executed(to: Q_Address, amount: u128, digest: Q_Hash);
  event Rotated(digest: Q_Hash);
}
