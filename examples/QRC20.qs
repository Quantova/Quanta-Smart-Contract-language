import { Map } from "quantova/stdlib";
contract QRC20 {
  asset QAT;
  state {
    owner: Q_Address;
    total_supply: u128;
    balances: Map<Q_Address, u128>;
  }
  genesis {
    owner = deploy_params.owner;
    total_supply = deploy_params.initial_supply;
  }
  entry mint(order: MintOrder signed by owner)
    mints QAT
    writes(total_supply, balances)
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
