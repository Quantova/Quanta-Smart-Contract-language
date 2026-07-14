import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Marketplace {
  asset ITEM;
  state {
    owner: Q_Address;
    escrowed: Q_Asset<QTOV>;
    listings: Map<Q_Id, u128>;
    fee_bps: u16 = 250;
  }
  genesis {
    owner = deployer;
  }
  invariant fee_bps <= 10_000;
  entry list_item(order: ListOrder signed by owner)
    mints ITEM
    writes(listings)
  {
    listings.credit(order.id, order.price);
    emit Listed(order.id, order.price);
  }
  entry buy(order: BuyOrder, payment: sealed Q_Asset<QTOV>)
    conserves QTOV
    writes(escrowed)
    limits payment.amount >= order.price
  {
    guard payment.amount >= order.price;
    escrowed.merge(payment);
    send(order.seller, escrowed.split(order.price));
    emit Sold(order.id, order.buyer, order.price);
  }
  event Listed(id: Q_Id, price: u128);
  event Sold(id: Q_Id, buyer: Q_Address, price: u128);
}
