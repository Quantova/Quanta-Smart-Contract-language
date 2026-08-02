import { Q_Asset } from "quantova/primitives";
contract Escrow {
  state {
    buyer: Q_Address;
    seller: Q_Address;
    arbiter: Q_Address;
    holding: Q_Asset<QTOV>;
    price: u128;
    funded: u8 = 0;
    released: u8 = 0;
  }
  genesis {
    buyer = deploy_params.buyer;
    seller = deploy_params.seller;
    arbiter = deploy_params.arbiter;
    price = deploy_params.price;
  }
  invariant funded <= 1;
  invariant released <= 1;
  entry fund(payment: sealed Q_Asset<QTOV>)
    conserves QTOV
    writes(holding, funded)
    denies funded == 1
  {
    guard payment.amount == price;
    funded = 1;
    holding.merge(payment);
    emit Funded(buyer, payment.amount);
  }
  entry release(order: ReleaseOrder signed by arbiter)
    conserves QTOV
    writes(holding, released)
    denies released == 1
  {
    released = 1;
    let out = holding.split(price);
    send(seller, out);
    emit Released(seller, price);
  }
  event Funded(from_addr: Q_Address, amount: u128);
  event Released(to: Q_Address, amount: u128);
}
