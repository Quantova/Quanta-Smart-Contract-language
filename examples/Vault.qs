import { Q_Asset, Q_Sig } from "quantova/primitives";
contract Vault {
  state {
    owner: Q_Address;
    reserve: Q_Asset<QTOV>;
    daily_cap: u64 = 50_000;
    spent_today: u64;
    last_reset: u64;
  }
  genesis {
    owner = deployer;
  }
  invariant spent_today <= daily_cap;
  entry deposit(funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(reserve)
  {
    reserve.merge(funds);
    emit Funded(funds.amount);
  }
  entry withdraw(req: WithdrawReq signed by owner)
    writes(reserve, spent_today)
    conserves QTOV
    limits req.amount <= daily_cap - spent_today
  {
    guard reserve.amount >= req.amount;
    let payout = reserve.split(req.amount);
    spent_today += req.amount;
    send(req.to, payout);
    emit Withdrawn(req.to, req.amount);
  }
  entry roll_day(req: RollDay signed by owner)
    writes(spent_today, last_reset)
    after 24 hours from last_reset
  {
    spent_today = 0;
    last_reset = now;
    emit DayRolled();
  }
  event Funded(amount: u128);
  event Withdrawn(to: Q_Address, amount: u128);
  event DayRolled();
}
