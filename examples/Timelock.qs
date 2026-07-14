import { Q_Asset } from "quantova/primitives";
contract Timelock {
  state {
    owner: Q_Address;
    vault: Q_Asset<QTOV>;
    unlock: Time = 2027-12-31;
  }
  genesis {
    owner = deployer;
  }
  entry withdraw(order: WithdrawOrder signed by owner)
    conserves QTOV
    writes(vault)
    after unlock
  {
    guard vault.amount >= order.amount;
    let out = vault.split(order.amount);
    send(order.to, out);
    emit Withdrawn(order.to, order.amount);
  }
  entry deposit(funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(vault)
  {
    vault.merge(funds);
    emit Deposited(caller, funds.amount);
  }
  event Withdrawn(to: Q_Address, amount: u128);
  event Deposited(from_addr: Q_Address, amount: u128);
}
