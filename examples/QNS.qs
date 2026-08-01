import { Map } from "quantova/stdlib";
import { Q_Asset, Quorum } from "quantova/primitives";
contract QNS {
  state {
    guardians: GuardianSet<7>;
    base_3: u64;
    base_4: u64;
    base_5_plus: u64;
    grace_period: u64;
    auction_duration: u64;
    start_premium: u64;
    interval: u64;
    vault: Q_Asset<QTOV>;
    expiry_of: Map<Q_Address, u64>;
    owner_of: Map<Q_Address, Q_Address>;
    resolved_of: Map<Q_Address, Q_Address>;
    primary_of: Map<Q_Address, Q_Address>;
    reserved: Map<Q_Address, u64>;
  }
  genesis {
    guardians = deploy_params.guardians;
    base_3 = deploy_params.base_3;
    base_4 = deploy_params.base_4;
    base_5_plus = deploy_params.base_5_plus;
    grace_period = deploy_params.grace_period;
    auction_duration = deploy_params.auction_duration;
    start_premium = deploy_params.start_premium;
    interval = deploy_params.interval;
  }
  entry register(label: sealed Q_Name, years: u64, payment: sealed Q_Asset<QTOV>)
    reads(base_3, base_4, base_5_plus, grace_period, auction_duration, reserved)
    writes(owner_of, expiry_of, vault)
    conserves QTOV
  {
    guard label.len >= 3;
    guard reserved.get(label) == 0;
    guard expiry_of.get(label) == 0 || now >= expiry_of.get(label) + grace_period + auction_duration;
    guard payment.amount >= (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years;
    owner_of.set(label, caller);
    expiry_of.set(label, now + years * 31536000);
    vault.merge(payment);
    emit Registered(label, caller, now + years * 31536000, years);
  }
  entry renew(label: sealed Q_Name, years: u64, payment: sealed Q_Asset<QTOV>)
    reads(base_3, base_4, base_5_plus, grace_period)
    writes(expiry_of, vault)
    conserves QTOV
  {
    guard label.len >= 3;
    guard expiry_of.get(label) > 0;
    guard now <= expiry_of.get(label) + grace_period;
    guard payment.amount >= (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years;
    expiry_of.set(label, expiry_of.get(label) + years * 31536000);
    vault.merge(payment);
    emit Renewed(label, expiry_of.get(label), years);
  }
  entry claim_premium(label: sealed Q_Name, years: u64, payment: sealed Q_Asset<QTOV>)
    reads(base_3, base_4, base_5_plus, grace_period, auction_duration, start_premium, interval, reserved)
    writes(owner_of, expiry_of, vault)
    conserves QTOV
  {
    guard label.len >= 3;
    guard reserved.get(label) == 0;
    guard now >= expiry_of.get(label) + grace_period;
    guard now < expiry_of.get(label) + grace_period + auction_duration;
    guard payment.amount >= (start_premium >> ((now - (expiry_of.get(label) + grace_period)) / interval)) + (base_3 * (3 / label.len) + base_4 * ((4 / label.len) - (3 / label.len)) + base_5_plus * (1 - (4 / label.len))) * years;
    owner_of.set(label, caller);
    expiry_of.set(label, now + years * 31536000);
    vault.merge(payment);
    emit PremiumClaimed(label, caller, now + years * 31536000, years);
  }
  entry reserve(order: NameReservation, approvals: Quorum<4 of 7, guardians>)
    writes(reserved)
  {
    reserved.set(order.name, 1);
    emit Reserved(order.name);
  }
  entry release(order: NameReservation, approvals: Quorum<4 of 7, guardians>)
    writes(reserved)
  {
    reserved.set(order.name, 0);
    emit Released(order.name);
  }
  entry set_resolved(label: Q_Name, target: Q_Address)
    reads(owner_of, expiry_of)
    writes(resolved_of)
  {
    guard owner_of.get(label) == caller;
    guard now < expiry_of.get(label);
    resolved_of.set(label, target);
    emit Resolved(label, caller, target);
  }
  entry set_primary(label: Q_Name)
    reads(owner_of, expiry_of)
    writes(primary_of)
  {
    guard owner_of.get(label) == caller;
    guard now < expiry_of.get(label);
    primary_of.set(caller, label);
    emit PrimarySet(caller, label);
  }
  entry transfer(label: Q_Name, to: Q_Address)
    reads(owner_of)
    writes(owner_of)
  {
    guard owner_of.get(label) == caller;
    owner_of.set(label, to);
    emit Transferred(label, caller, to);
  }
  entry withdraw(order: Sweep, approvals: Quorum<5 of 7, guardians>)
    conserves QTOV
    writes(vault)
  {
    guard vault.amount >= order.amount;
    let out = vault.split(order.amount);
    send(order.to, out);
    emit Swept(order.to, order.amount);
  }
  event Registered(name: Q_Address, owner: Q_Address, expiry: u64, term: u64);
  event Renewed(name: Q_Address, expiry: u64, term: u64);
  event PremiumClaimed(name: Q_Address, owner: Q_Address, expiry: u64, term: u64);
  event Reserved(name: Q_Address);
  event Released(name: Q_Address);
  event Resolved(name: Q_Address, owner: Q_Address, target: Q_Address);
  event PrimarySet(owner: Q_Address, name: Q_Address);
  event Transferred(name: Q_Address, prior: Q_Address, to: Q_Address);
  event Swept(to: Q_Address, amount: u128);
}
