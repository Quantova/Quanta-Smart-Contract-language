import { Q_Sig } from "quantova/primitives";
import { Registry, Map } from "quantova/stdlib";
contract NameRegistry {
  state {
    admin: Q_Address;
    names: Registry<Q_Name>;
    owners: Map<Q_Name, Q_Address>;
    fee: u64 = 100;
  }
  genesis {
    admin = deployer;
  }
  entry register(claim: NameClaim signed by admin)
    writes(names, owners)
    denies names.contains(claim.name)
  {
    names.insert(claim.name);
    owners.set(claim.name, claim.owner);
    emit Registered(claim.name, claim.owner);
  }
  entry release_name(order: ReleaseName signed by admin)
    writes(names, owners)
    denies !names.contains(order.name)
  {
    names.remove(order.name);
    emit ReleasedName(order.name);
  }
  event Registered(name: Q_Name, owner: Q_Address);
  event ReleasedName(name: Q_Name);
}
