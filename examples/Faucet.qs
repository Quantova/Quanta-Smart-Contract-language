import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Faucet {
  state {
    owner: Q_Address;
    tank: Q_Asset<QTOV>;
    drip: u64 = 10;
    last_claim: Map<Q_Address, Time>;
  }
  genesis {
    owner = deployer;
  }
  invariant drip <= 1_000;
  entry claim(order: DripOrder signed by owner)
    conserves QTOV
    writes(tank, last_claim)
    limits order.amount <= drip
  {
    guard tank.amount >= order.amount;
    let out = tank.split(order.amount);
    send(order.to, out);
    last_claim.credit(order.to, order.at);
    emit Dripped(order.to, order.amount);
  }
  entry refill(funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(tank)
  {
    tank.merge(funds);
    emit Refilled(caller, funds.amount);
  }
  event Dripped(to: Q_Address, amount: u128);
  event Refilled(from_addr: Q_Address, amount: u128);
}
