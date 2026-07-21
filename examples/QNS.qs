import { Map, Registry } from "quantova/stdlib";
contract QNS {
  state {
    admin: Q_Address;
    purchase_fee: u64;
    renewal_fee: u64;
    vault: u64;
    registered: Registry<Q_Address>;
    expiry_of: Map<Q_Address, u64>;
    owner_of: Map<Q_Address, Q_Address>;
    resolved_of: Map<Q_Address, Q_Address>;
  }
  genesis {
    admin = deploy_params.admin;
    purchase_fee = deploy_params.purchase_fee;
    renewal_fee = deploy_params.renewal_fee;
  }
  entry register(name: Q_Address, until: u64)
    reads(purchase_fee)
    writes(registered, expiry_of, owner_of, vault)
    after expiry_of.contains(name)
    limits vault + purchase_fee <= 9000000000000000000
  {
    owner_of.set(name, caller);
    expiry_of.debit(name, expiry_of.contains(name));
    expiry_of.credit(name, until);
    registered.insert(name);
    vault += purchase_fee;
    emit Registered(name, caller, until);
  }
  entry renew(name: Q_Address, years: u64)
    reads(renewal_fee, registered)
    writes(expiry_of, vault)
    limits vault + renewal_fee * years <= 9000000000000000000
  {
    guard registered.contains(name);
    expiry_of.credit(name, years * 31536000);
    vault += renewal_fee * years;
    emit Renewed(name, years);
  }
  entry set_resolved(name: Q_Address, target: Q_Address)
    reads(owner_of, registered)
    writes(resolved_of)
  {
    guard owner_of.get(name) == caller;
    guard registered.contains(name);
    resolved_of.set(name, target);
    emit Resolved(name, caller, target);
  }
  entry transfer(name: Q_Address, to: Q_Address)
    reads(owner_of)
    writes(owner_of)
  {
    guard owner_of.get(name) == caller;
    owner_of.set(name, to);
    emit Transferred(name, caller, to);
  }
  entry withdraw(order: Sweep signed by admin)
    reads(admin)
    writes(vault)
  {
    vault -= order.amount;
    emit Swept(order.amount);
  }
  event Registered(name: Q_Address, owner: Q_Address, until: u64);
  event Renewed(name: Q_Address, years: u64);
  event Resolved(name: Q_Address, owner: Q_Address, target: Q_Address);
  event Transferred(name: Q_Address, prior: Q_Address, to: Q_Address);
  event Swept(amount: u64);
}
