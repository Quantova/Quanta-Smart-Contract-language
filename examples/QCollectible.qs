import { Map } from "quantova/stdlib";
contract QCollectible {
  state {
    admin: Q_Address;
    supply: u64;
    owner_of: Map<Q_Id, Q_Address>;
    holdings: Map<Q_Address, u64>;
    content_of: Map<Q_Id, Q_Address>;
  }
  genesis {
    admin = deploy_params.admin;
  }
  entry mint(order: MintOrder signed by admin)
    reads(admin, owner_of)
    writes(owner_of, content_of, supply, holdings)
  {
    guard !owner_of.contains(order.id);
    owner_of.set(order.id, order.to);
    content_of.set(order.id, order.content);
    supply = checked(supply + 1);
    holdings.credit(order.to, 1);
    emit Minted(order.id, order.to, order.content);
  }
  entry transfer(id: Q_Id, to: Q_Address)
    reads(owner_of)
    writes(owner_of, holdings)
  {
    guard owner_of.get(id) == caller;
    owner_of.set(id, to);
    holdings.debit(caller, 1);
    holdings.credit(to, 1);
    emit Transferred(id, caller, to);
  }
  event Minted(id: Q_Id, to: Q_Address, content: Q_Address);
  event Transferred(id: Q_Id, prior: Q_Address, to: Q_Address);
}
