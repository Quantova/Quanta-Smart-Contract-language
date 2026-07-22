import { Q_Asset, Q_Sig } from "quantova/primitives";
import { Map, Registry } from "quantova/stdlib";
contract RegulatedToken {
  asset RTK;
  state {
    owner: Q_Address;
    total_supply: u128;
    max_supply: u128;
    balances: Map<Q_Address, u128>;
    frozen: Registry<Q_Address>;
  }
  genesis {
    owner = deploy_params.owner;
    total_supply = 0;
    max_supply = 1_000_000_000_000_000_000_000;
  }
  invariant total_supply <= max_supply;
  entry mint(order: MintOrder signed by owner)
    mints RTK
    writes(total_supply, balances)
    reads(frozen)
    limits total_supply + order.amount <= max_supply
    denies frozen.contains(order.to)
  {
    total_supply += order.amount;
    balances.credit(order.to, order.amount);
    emit Minted(order.to, order.amount);
  }
  entry transfer(to: Q_Address, amount: u64)
    reads(frozen)
    writes(balances)
  {
    guard amount > 0;
    guard !frozen.contains(caller);
    guard !frozen.contains(to);
    balances.debit(caller, amount);
    balances.credit(to, amount);
    emit Transferred(caller, to, amount);
  }
  entry burn(order: BurnOrder signed by owner)
    writes(total_supply, balances)
  {
    balances.debit(order.holder, order.amount);
    total_supply -= order.amount;
    emit Burned(order.holder, order.amount);
  }
  entry freeze(order: FreezeOrder signed by owner)
    writes(frozen)
  {
    frozen.insert(order.who);
    emit Frozen(order.who);
  }
  entry unfreeze(order: FreezeOrder signed by owner)
    writes(frozen)
  {
    frozen.remove(order.who);
    emit Unfrozen(order.who);
  }
  event Minted(to: Q_Address, amount: u128);
  event Transferred(sender: Q_Address, to: Q_Address, amount: u128);
  event Burned(holder: Q_Address, amount: u128);
  event Frozen(who: Q_Address);
  event Unfrozen(who: Q_Address);
}
