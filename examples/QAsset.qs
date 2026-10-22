import { Map } from "quantova/stdlib";
contract QAsset {
  asset QAT;
  state {
    owner: Q_Address;
    total_supply: u128;
    balances: Map<Q_Address, u128>;
    max_supply: u128 = 1_000_000_000_000_000_000_000_000;
  }
  genesis {
    owner = deploy_params.owner;
    total_supply = deploy_params.initial_supply;
    balances.credit(deploy_params.owner, deploy_params.initial_supply);
  }
  entry mint(order: MintOrder signed by owner)
    mints QAT
    reads(max_supply)
    writes(total_supply, balances)
    limits total_supply + order.amount <= max_supply
  {
    total_supply += order.amount;
    balances.credit(order.to, order.amount);
    emit Minted(order.to, order.amount);
  }
  entry transfer(to: Q_Address, amount: u128)
    writes(balances)
  {
    guard amount > 0;
    balances.debit(caller, amount);
    balances.credit(to, amount);
    emit Transferred(caller, to, amount);
  }
  event Minted(to: Q_Address, amount: u128);
  event Transferred(sender: Q_Address, to: Q_Address, amount: u128);
}
