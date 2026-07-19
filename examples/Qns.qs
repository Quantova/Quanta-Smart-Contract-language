import { Q_Sig } from "quantova/primitives";
import { Registry, Map } from "quantova/stdlib";
contract Qns {
  state {
    registrar: Q_Address;
    taken: Registry<Q_Name>;
    owner_of: Map<Q_Name, Q_Address>;
    expiry_of: Map<Q_Name, u64>;
    primary_of: Map<Q_Address, Q_Name>;
  }
  genesis {
    registrar = deployer;
  }
  entry claim(order: NameClaim signed by registrar)
    writes(taken, owner_of, expiry_of)
    denies taken.contains(order.name)
  {
    taken.insert(order.name);
    owner_of.credit(order.name, order.owner);
    expiry_of.credit(order.name, order.until);
    emit Claimed(order.name, order.owner, order.until);
  }
  entry renew(order: Renewal signed by registrar)
    writes(expiry_of)
    denies !taken.contains(order.name)
  {
    expiry_of.credit(order.name, order.added);
    emit Renewed(order.name, order.added);
  }
  entry set_primary(order: SetPrimary signed by registrar)
    writes(primary_of)
  {
    primary_of.credit(order.owner, order.name);
    emit PrimarySet(order.owner, order.name);
  }
  entry release(order: Release signed by registrar)
    writes(taken, owner_of)
    denies !taken.contains(order.name)
  {
    owner_of.debit(order.name, order.owner);
    taken.remove(order.name);
    emit Released(order.name);
  }
  event Claimed(name: Q_Name, owner: Q_Address, until: u64);
  event Renewed(name: Q_Name, added: u64);
  event PrimarySet(owner: Q_Address, name: Q_Name);
  event Released(name: Q_Name);
}
