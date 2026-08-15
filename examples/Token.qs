import { Q_Asset, Q_Sig } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Token {
  asset TKN;
  state {
    owner: Q_Address;
    total_supply: u128;
    max_supply: u128 = 1_000_000_000;
    balances: Map<Q_Address, u128>;
  }
  genesis {
    owner = deployer;
    total_supply = 0;
  }
  invariant total_supply <= max_supply;
  entry mint_to(order: MintOrder signed by owner)
    mints TKN
    writes(total_supply, balances)
    limits total_supply + order.amount <= max_supply
  {
    total_supply += order.amount;
    balances.credit(order.to, order.amount);
    emit Minted(order.to, order.amount);
  }
  entry transfer(to: Q_Address, amount: u64)
    writes(balances)
  {
    guard amount > 0;
    balances.debit(caller, amount);
    balances.credit(to, amount);
    emit Transferred(caller, to, amount);
  }
  entry burn(amount: u64)
    writes(total_supply, balances)
  {
    guard amount > 0;
    balances.debit(caller, amount);
    total_supply -= amount;
    emit Burned(caller, amount);
  }
  event Minted(to: Q_Address, amount: u128);
  event Transferred(sender: Q_Address, to: Q_Address, amount: u128);
  event Burned(sender: Q_Address, amount: u128);
}
