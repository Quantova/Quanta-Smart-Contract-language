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
  entry transfer(funds: Q_Asset<TKN>, to: Q_Address)
    conserves TKN
    writes(balances)
  {
    guard funds.amount > 0;
    send(to, funds);
    emit Transferred(caller, to, funds.amount);
  }
  entry burn(funds: Q_Asset<TKN>)
    burns TKN
    writes(total_supply)
  {
    total_supply -= funds.amount;
    emit Burned(caller, funds.amount);
  }
  event Minted(to: Q_Address, amount: u128);
  event Transferred(sender: Q_Address, to: Q_Address, amount: u128);
  event Burned(sender: Q_Address, amount: u128);
}
