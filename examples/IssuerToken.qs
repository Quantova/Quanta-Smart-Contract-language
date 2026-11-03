import { Q_Asset, Quorum } from "quantova/primitives";
import { Map, Registry } from "quantova/stdlib";
contract IssuerToken {
  asset TOKEN;
  state {
    guardians: GuardianSet<5>;
    total_supply: u128;
    max_supply: u128 = 1_000_000_000;
    paused: bool;
    balances: Map<Q_Address, u128>;
    frozen: Registry<Q_Address>;
  }
  genesis {
    total_supply = 0;
    guardians = deploy_params.guardians;
  }
  invariant total_supply <= max_supply;
  entry mint(order: MintOrder, approvals: Quorum<3 of 5, guardians>)
    mints TOKEN
    writes(total_supply, balances)
    limits total_supply + order.amount <= max_supply
  {
    total_supply += order.amount;
    balances.credit(order.to, mint(order.amount));
    emit Minted(order.to, order.amount, approvals.signer_bits);
  }
  entry burn(order: BurnOrder, approvals: Quorum<3 of 5, guardians>)
    writes(total_supply, balances)
  {
    balances.debit(order.holder, order.amount);
    total_supply -= order.amount;
    emit Burned(order.amount, approvals.signer_bits);
  }
  entry transfer(to: Q_Address, amount: u64)
    reads(paused, frozen)
    writes(balances)
  {
    guard !paused;
    guard !frozen.contains(caller);
    guard !frozen.contains(to);
    balances.debit(caller, amount);
    balances.credit(to, amount);
    emit Transferred(caller, to, amount);
  }
  entry freeze(target: FreezeOrder, approvals: Quorum<3 of 5, guardians>)
    writes(frozen)
  {
    frozen.insert(target.who);
    emit Frozen(target.who, approvals.signer_bits);
  }
  entry unfreeze(target: FreezeOrder, approvals: Quorum<3 of 5, guardians>)
    writes(frozen)
  {
    frozen.remove(target.who);
    emit Unfrozen(target.who, approvals.signer_bits);
  }
  entry clawback(order: ClawbackOrder, approvals: Quorum<3 of 5, guardians>)
    reads(frozen)
    writes(balances)
  {
    guard frozen.contains(order.holder);
    balances.debit(order.holder, order.amount);
    balances.credit(order.recovery, order.amount);
    emit ClawedBack(order.holder, order.recovery, order.amount, order.evidence);
  }
  entry pause(approvals: Quorum<3 of 5, guardians>)
    writes(paused)
  {
    paused = 1;
    emit Paused(approvals.signer_bits);
  }
  entry unpause(approvals: Quorum<3 of 5, guardians>)
    writes(paused)
  {
    paused = 0;
    emit Unpaused(approvals.signer_bits);
  }
  event Minted(to: Q_Address, amount: u128, signer_bits: Q_Word64);
  event Burned(amount: u128, signer_bits: Q_Word64);
  event Transferred(sender: Q_Address, to: Q_Address, amount: u128);
  event Frozen(who: Q_Address, signer_bits: Q_Word64);
  event Unfrozen(who: Q_Address, signer_bits: Q_Word64);
  event ClawedBack(holder: Q_Address, recovery: Q_Address, amount: u128, evidence: Q_Word64);
  event Paused(signer_bits: Q_Word64);
  event Unpaused(signer_bits: Q_Word64);
}
