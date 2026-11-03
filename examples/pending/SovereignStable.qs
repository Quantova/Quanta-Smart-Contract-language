import { Q_Asset, Quorum } from "quantova/primitives";
import { Registry } from "quantova/stdlib";
contract SovereignStable {
  asset QSGD;
  state {
    issuance_board: GuardianSet<5>;
    monthly_ceiling: u128;
    issued_this_month: u128;
    sanctions: Registry<Q_Address>;
    board_rotation_armed: u64;
    month_reset: u64;
  }
  genesis {
    issuance_board = deploy_params.board;
    monthly_ceiling = deploy_params.ceiling;
    month_reset = now;
  }
  invariant issued_this_month <= monthly_ceiling;
  entry issue(order: IssuanceOrder, approvals: Quorum<3 of 5, issuance_board>)
    mints QSGD
    writes(issued_this_month)
    limits order.amount <= monthly_ceiling - issued_this_month
  {
    issued_this_month += order.amount;
    send(order.treasury, mint(order.amount));
    emit Issued(order.amount, approvals.signer_bits);
  }
  entry transfer(funds: Q_Asset<QSGD>, to: Q_Address)
    conserves QSGD
    denies sanctions.contains(to)
    denies sanctions.contains(caller)
  {
    send(to, funds);
  }
  entry roll_month(approvals: Quorum<3 of 5, issuance_board>)
    writes(issued_this_month, month_reset)
    after 30 days from month_reset
  {
    issued_this_month = 0;
    month_reset = now;
    emit MonthRolled(approvals.signer_bits);
  }
  entry sanction(order: SanctionOrder, approvals: Quorum<3 of 5, issuance_board>)
    writes(sanctions)
    denies sanctions.contains(order.who)
  {
    sanctions.insert(order.who);
    emit Sanctioned(order.who, approvals.signer_bits);
  }
  entry unsanction(order: SanctionOrder, approvals: Quorum<3 of 5, issuance_board>)
    writes(sanctions)
    denies !sanctions.contains(order.who)
  {
    sanctions.remove(order.who);
    emit Unsanctioned(order.who, approvals.signer_bits);
  }
  entry arm_board_rotation(approvals: Quorum<4 of 5, issuance_board>)
    writes(board_rotation_armed)
  {
    board_rotation_armed = now;
    emit BoardRotationArmed(approvals.signer_bits);
  }
  entry rotate_board(new_set: GuardianSet<5>,
                     approvals: Quorum<4 of 5, issuance_board>)
    writes(issuance_board, board_rotation_armed)
    after 48 hours from board_rotation_armed
    denies board_rotation_armed == 0
  {
    issuance_board = new_set;
    board_rotation_armed = 0;
    emit BoardRotated(approvals.signer_bits);
  }
  event Issued(amount: u128, signer_bits: Q_Word64);
  event BoardRotationArmed(signer_bits: Q_Word64);
  event BoardRotated(signer_bits: Q_Word64);
  event MonthRolled(signer_bits: Q_Word64);
  event Sanctioned(who: Q_Address, signer_bits: Q_Word64);
  event Unsanctioned(who: Q_Address, signer_bits: Q_Word64);
}
