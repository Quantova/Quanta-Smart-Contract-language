import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Marketplace {
  state {
    owner: Q_Address;
    escrowed: Q_Asset<QTOV>;
    listings: Map<Q_Id, u64>;
    item_owner: Map<Q_Id, Q_Address>;
  }
  genesis {
    owner = deployer;
  }
  entry list_item(order: ListOrder signed by owner)
    writes(listings, item_owner)
  {
    guard order.price > 0;
    item_owner.set(order.id, owner);
    listings.set(order.id, order.price);
    emit Listed(order.id, order.price);
  }
  entry buy(id: Q_Id, payment: sealed Q_Asset<QTOV>)
    reads(listings)
    conserves QTOV
    writes(escrowed, item_owner, listings)
  {
    guard listings.get(id) > 0;
    guard payment.amount == listings.get(id);
    escrowed.merge(payment);
    send(owner, escrowed.split(listings.get(id)));
    item_owner.set(id, caller);
    emit Sold(id, caller, listings.get(id));
    listings.set(id, 0);
  }
  event Listed(id: Q_Id, price: u64);
  event Sold(id: Q_Id, buyer: Q_Address, price: u64);
}
