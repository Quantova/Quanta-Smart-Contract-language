import { Registry, Map } from "quantova/stdlib";
contract NameRegistry {
  state {
    admin: Q_Address;
    names: Registry<Q_Name>;
    owners: Map<Q_Name, Q_Address>;
  }
  genesis {
    admin = deployer;
  }
  entry register(name: Q_Name, owner: Q_Address)
    writes(names, owners)
    denies names.contains(name)
  {
    guard caller == admin;
    names.insert(name);
    owners.set(name, owner);
    emit Registered(name, owner);
  }
  entry release_name(name: Q_Name)
    writes(names, owners)
    denies !names.contains(name)
  {
    guard caller == admin;
    names.remove(name);
    owners.remove(name);
    emit ReleasedName(name);
  }
  event Registered(name: Q_Name, owner: Q_Address);
  event ReleasedName(name: Q_Name);
}
