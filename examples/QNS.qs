import { Map } from "quantova/stdlib";
contract QNS {
  state {
    admin: Q_Address;
    base_3: u64;
    base_4: u64;
    base_5_plus: u64;
    grace_period: u64;
    auction_duration: u64;
    start_premium: u64;
    interval: u64;
    vault: u64;
    expiry_of: Map<Q_Address, u64>;
    owner_of: Map<Q_Address, Q_Address>;
    resolved_of: Map<Q_Address, Q_Address>;
  }
  genesis {
    admin = deploy_params.admin;
    base_3 = deploy_params.base_3;
    base_4 = deploy_params.base_4;
    base_5_plus = deploy_params.base_5_plus;
    grace_period = deploy_params.grace_period;
    auction_duration = deploy_params.auction_duration;
    start_premium = deploy_params.start_premium;
    interval = deploy_params.interval;
  }
  entry register(label: Q_Name, years: u64)
    reads(base_3, base_4, base_5_plus, grace_period, auction_duration)
    writes(owner_of, expiry_of, vault)
  {
    guard label.len >= 3;
    guard expiry_of.get(label) == 0 || now >= expiry_of.get(label) + grace_period + auction_duration;
    owner_of.set(label, caller);
    expiry_of.set(label, now + years * 31536000);
    vault = checked(vault + (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years);
    emit Registered(label, caller, now + years * 31536000, years);
  }
  entry renew(label: Q_Name, years: u64)
    reads(base_3, base_4, base_5_plus, grace_period)
    writes(expiry_of, vault)
  {
    guard label.len >= 3;
    guard expiry_of.get(label) > 0;
    guard now <= expiry_of.get(label) + grace_period;
    expiry_of.set(label, expiry_of.get(label) + years * 31536000);
    vault = checked(vault + (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years);
    emit Renewed(label, expiry_of.get(label), years);
  }
  entry claim_premium(label: Q_Name, years: u64)
    reads(base_3, base_4, base_5_plus, grace_period, auction_duration, start_premium, interval)
    writes(owner_of, expiry_of, vault)
  {
    guard label.len >= 3;
    guard now >= expiry_of.get(label) + grace_period;
    guard now < expiry_of.get(label) + grace_period + auction_duration;
    vault = checked(vault + (start_premium >> ((now - (expiry_of.get(label) + grace_period)) / interval)) + (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years);
    owner_of.set(label, caller);
    expiry_of.set(label, now + years * 31536000);
    emit PremiumClaimed(label, caller, now + years * 31536000, years);
  }
  entry set_resolved(label: Q_Name, target: Q_Address)
    reads(owner_of)
    writes(resolved_of)
  {
    guard owner_of.get(label) == caller;
    resolved_of.set(label, target);
    emit Resolved(label, caller, target);
  }
  entry transfer(label: Q_Name, to: Q_Address)
    reads(owner_of)
    writes(owner_of)
  {
    guard owner_of.get(label) == caller;
    owner_of.set(label, to);
    emit Transferred(label, caller, to);
  }
  entry withdraw(order: Sweep signed by admin)
    reads(admin)
    writes(vault)
  {
    vault -= order.amount;
    emit Swept(order.amount);
  }
  event Registered(name: Q_Address, owner: Q_Address, expiry: u64, term: u64);
  event Renewed(name: Q_Address, expiry: u64, term: u64);
  event PremiumClaimed(name: Q_Address, owner: Q_Address, expiry: u64, term: u64);
  event Resolved(name: Q_Address, owner: Q_Address, target: Q_Address);
  event Transferred(name: Q_Address, prior: Q_Address, to: Q_Address);
  event Swept(amount: u64);
}
