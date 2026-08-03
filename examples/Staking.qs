import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Staking {
  state {
    pool: Q_Asset<QTOV>;
    stakes: Map<Q_Address, u128>;
    total_staked: u128;
  }
  genesis {
    total_staked = 0;
  }
  invariant total_staked <= pool.amount;
  entry stake(funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(pool, stakes, total_staked)
  {
    guard funds.amount > 0;
    total_staked += funds.amount;
    pool.merge(funds);
    stakes.credit(caller, funds.amount);
    emit Staked(caller, funds.amount);
  }
  entry unstake(order: UnstakeOrder)
    conserves QTOV
    writes(pool, stakes, total_staked)
  {
    guard order.amount > 0;
    stakes.debit(caller, order.amount);
    total_staked -= order.amount;
    let out = pool.split(order.amount);
    send(caller, out);
    emit Unstaked(caller, order.amount);
  }
  event Staked(who: Q_Address, amount: u128);
  event Unstaked(who: Q_Address, amount: u128);
}
