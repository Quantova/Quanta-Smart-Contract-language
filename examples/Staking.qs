import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Staking {
  asset SREWARD;
  state {
    admin: Q_Address;
    pool: Q_Asset<QTOV>;
    stakes: Map<Q_Address, u128>;
    total_staked: u128;
    reward_rate: u16 = 5;
  }
  genesis {
    admin = deployer;
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
  entry unstake(order: UnstakeOrder signed by admin)
    conserves QTOV
    writes(pool, stakes, total_staked)
    limits order.amount <= total_staked
  {
    total_staked -= order.amount;
    let out = pool.split(order.amount);
    send(order.to, out);
    emit Unstaked(order.to, order.amount);
  }
  event Staked(who: Q_Address, amount: u128);
  event Unstaked(who: Q_Address, amount: u128);
}
