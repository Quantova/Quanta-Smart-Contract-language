import { Q_Asset, Quorum } from "quantova/primitives";
import { Registry } from "quantova/stdlib";
contract SovereignStable {
  asset QSGD;
  state {
    issuance_board: GuardianSet<5>;
    monthly_ceiling: u128;
    issued_this_month: u128;
    sanctions: Registry<Q_Address>;
  }
  genesis {
    issuance_board = deploy_params.board;
    monthly_ceiling = deploy_params.ceiling;
  }
  invariant issued_this_month <= monthly_ceiling;
  entry issue(order: IssuanceOrder, approvals: Quorum<3 of 5, issuance_board>)
    mints QSGD
    writes(issued_this_month)
    limits order.amount <= monthly_ceiling - issued_this_month
  {
    issued_this_month += order.amount;
    send(order.treasury, mint(order.amount));
    emit Issued(order.amount, approvals.digest);
  }
  entry transfer(funds: Q_Asset<QSGD>, to: Q_Address)
    conserves QSGD
    denies sanctions.contains(to)
  {
    send(to, funds);
  }
  entry rotate_board(new_set: GuardianSet<5>,
                     approvals: Quorum<4 of 5, issuance_board>)
    writes(issuance_board)
    after 48 hours from approvals.first
  {
    issuance_board = new_set;
    emit BoardRotated(approvals.digest);
  }
  event Issued(amount: u128, digest: Q_Hash);
  event BoardRotated(digest: Q_Hash);
}
