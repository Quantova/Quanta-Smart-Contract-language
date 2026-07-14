import { Q_Asset } from "quantova/primitives";
contract Auction {
  state {
    seller: Q_Address;
    highest_bid: u128;
    highest_bidder: Q_Address;
    pot: Q_Asset<QTOV>;
    closed: u8 = 0;
  }
  genesis {
    seller = deploy_params.seller;
  }
  invariant closed <= 1;
  entry bid(offer: sealed Bid, funds: Q_Asset<QTOV>)
    conserves QTOV
    writes(highest_bid, highest_bidder, pot)
    denies closed == 1
    limits offer.amount > highest_bid
  {
    guard funds.amount >= offer.amount;
    highest_bid = offer.amount;
    highest_bidder = offer.bidder;
    pot.merge(funds);
    emit BidPlaced(offer.bidder, offer.amount);
  }
  entry settle(order: SettleOrder signed by seller)
    conserves QTOV
    writes(closed, pot)
    denies closed == 1
  {
    closed = 1;
    let proceeds = pot.split(highest_bid);
    send(seller, proceeds);
    emit Settled(highest_bidder, highest_bid);
  }
  event BidPlaced(bidder: Q_Address, amount: u128);
  event Settled(winner: Q_Address, amount: u128);
}
