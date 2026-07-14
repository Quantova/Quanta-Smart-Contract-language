import { Q_Asset } from "quantova/primitives";
import { Registry } from "quantova/stdlib";
contract Payroll {
  state {
    employer: Q_Address;
    treasury: Q_Asset<QTOV>;
    staff: Registry<Q_Address>;
    period_cap: u128 = 500_000;
    paid_this_period: u128;
  }
  genesis {
    employer = deployer;
    paid_this_period = 0;
  }
  invariant paid_this_period <= period_cap;
  entry pay(order: PayOrder signed by employer)
    conserves QTOV
    writes(treasury, paid_this_period)
    reads(staff)
    denies !staff.contains(order.worker)
    limits paid_this_period + order.amount <= period_cap
  {
    guard treasury.amount >= order.amount;
    paid_this_period += order.amount;
    let out = treasury.split(order.amount);
    send(order.worker, out);
    emit Paid(order.worker, order.amount);
  }
  entry hire(order: HireOrder signed by employer)
    writes(staff)
    denies staff.contains(order.worker)
  {
    staff.insert(order.worker);
    emit Hired(order.worker);
  }
  event Paid(to: Q_Address, amount: u128);
  event Hired(worker: Q_Address);
}
