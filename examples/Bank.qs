import { Q_Asset } from "quantova/primitives";
contract Bank {
  state {
    owner: Q_Address;
    vault: Q_Asset<QTOV>;
    balance: u128;
  }
  genesis {
    owner = deployer;
  }
  entry deposit(funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(vault, balance)
  {
    balance += funds.amount;
    vault.merge(funds);
    emit Deposited(caller, funds.amount);
  }
  entry withdraw(order: WithdrawOrder signed by owner)
    conserves QTOV
    writes(vault, balance)
  {
    guard balance >= order.amount;
    let out = vault.split(order.amount);
    send(order.to, out);
    balance -= order.amount;
    emit Withdrawn(order.to, order.amount);
  }
  event Deposited(from_addr: Q_Address, amount: u128);
  event Withdrawn(to: Q_Address, amount: u128);
}
