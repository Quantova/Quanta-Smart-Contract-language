import { Q_Asset } from "quantova/primitives";
import { Map } from "quantova/stdlib";
contract Pool {
  state {
    token_a: Q_Address;
    token_b: Q_Address;
    reserve_a: u128;
    reserve_b: u128;
    total_shares: u128;
    shares: Map<Q_Address, u64>;
    pending_a: Map<Q_Address, u64>;
    max_reserve: u128 = 1_000_000_000_000_000;
    vault: Q_Asset<QTOV>;
  }
  genesis {
    token_a = deploy_params.token_a;
    token_b = deploy_params.token_b;
    reserve_a = 0;
    reserve_b = 0;
    total_shares = 0;
  }
  entry deposit_a(funds: Q_Asset<QTOV>)
    reads(token_a)
    writes(pending_a, vault)
    conserves QTOV
  {
    guard in_asset == token_a;
    pending_a.credit(caller, funds.amount);
    vault.merge(funds);
    emit Deposited(caller, token_a, funds.amount);
  }
  entry seed_liquidity(funds: Q_Asset<QTOV>)
    reads(token_b, pending_a, total_shares)
    writes(pending_a, reserve_a, reserve_b, total_shares, shares, vault)
    conserves QTOV
  {
    guard in_asset == token_b;
    guard total_shares == 0;
    guard pending_a.get(caller) > 0;
    guard funds.amount > 0;
    reserve_a = pending_a.get(caller);
    reserve_b = funds.amount;
    total_shares = pending_a.get(caller);
    shares.credit(caller, pending_a.get(caller));
    pending_a.debit(caller, pending_a.get(caller));
    vault.merge(funds);
    emit LiquidityAdded(caller, reserve_a, funds.amount, reserve_a);
  }
  entry provide_liquidity(funds: Q_Asset<QTOV>, min_shares: u128)
    reads(token_b, pending_a, reserve_a, reserve_b, total_shares, max_reserve)
    writes(pending_a, reserve_a, reserve_b, total_shares, shares, vault)
    conserves QTOV
    limits reserve_b + funds.amount <= max_reserve && reserve_a + funds.amount <= max_reserve && total_shares + funds.amount <= max_reserve
  {
    guard in_asset == token_b;
    guard total_shares > 0;
    guard reserve_b > 0;
    guard funds.amount > 0;
    guard (funds.amount * reserve_a) / reserve_b > 0;
    guard (funds.amount * total_shares) / reserve_b >= min_shares;
    guard (funds.amount * total_shares) / reserve_b > 0;
    guard pending_a.get(caller) >= (funds.amount * reserve_a) / reserve_b;
    shares.credit(caller, (funds.amount * total_shares) / reserve_b);
    total_shares = total_shares + (funds.amount * total_shares) / reserve_b;
    pending_a.debit(caller, (funds.amount * reserve_a) / reserve_b);
    reserve_a = reserve_a + (funds.amount * reserve_a) / reserve_b;
    reserve_b = reserve_b + funds.amount;
    vault.merge(funds);
    emit LiquidityAdded(caller, funds.amount, funds.amount, min_shares);
  }
  entry remove_liquidity(amount: u128)
    reads(shares, reserve_a, reserve_b, total_shares, token_a, token_b)
    writes(shares, reserve_a, reserve_b, total_shares)
  {
    guard amount > 0;
    guard shares.get(caller) >= amount;
    guard total_shares >= amount;
    guard (amount * reserve_a) / total_shares > 0;
    guard (amount * reserve_b) / total_shares > 0;
    guard reserve_a > (amount * reserve_a) / total_shares;
    guard reserve_b > (amount * reserve_b) / total_shares;
    shares.debit(caller, amount);
    send_asset(token_a, caller, (amount * reserve_a) / total_shares);
    send_asset(token_b, caller, (amount * reserve_b) / total_shares);
    reserve_a = reserve_a - (amount * reserve_a) / total_shares;
    reserve_b = reserve_b - (amount * reserve_b) / total_shares;
    total_shares = total_shares - amount;
    emit LiquidityRemoved(caller, amount);
  }
  entry swap_a_for_b(funds: Q_Asset<QTOV>, min_out: u128)
    reads(token_a, token_b, reserve_a, reserve_b, max_reserve)
    writes(reserve_a, reserve_b, vault)
    conserves QTOV
    limits reserve_a + funds.amount <= max_reserve
  {
    guard in_asset == token_a;
    guard reserve_a > 0;
    guard reserve_b > 0;
    guard funds.amount > 0;
    guard (funds.amount * 997 * reserve_b) / (reserve_a * 1000 + funds.amount * 997) >= min_out;
    guard (funds.amount * 997 * reserve_b) / (reserve_a * 1000 + funds.amount * 997) > 0;
    guard reserve_b > (funds.amount * 997 * reserve_b) / (reserve_a * 1000 + funds.amount * 997);
    send_asset(token_b, caller, (funds.amount * 997 * reserve_b) / (reserve_a * 1000 + funds.amount * 997));
    reserve_b = reserve_b - (funds.amount * 997 * reserve_b) / (reserve_a * 1000 + funds.amount * 997);
    reserve_a = reserve_a + funds.amount;
    vault.merge(funds);
    emit Swapped(caller, token_a, funds.amount, min_out);
  }
  entry swap_b_for_a(funds: Q_Asset<QTOV>, min_out: u128)
    reads(token_a, token_b, reserve_a, reserve_b, max_reserve)
    writes(reserve_a, reserve_b, vault)
    conserves QTOV
    limits reserve_b + funds.amount <= max_reserve
  {
    guard in_asset == token_b;
    guard reserve_a > 0;
    guard reserve_b > 0;
    guard funds.amount > 0;
    guard (funds.amount * 997 * reserve_a) / (reserve_b * 1000 + funds.amount * 997) >= min_out;
    guard (funds.amount * 997 * reserve_a) / (reserve_b * 1000 + funds.amount * 997) > 0;
    guard reserve_a > (funds.amount * 997 * reserve_a) / (reserve_b * 1000 + funds.amount * 997);
    send_asset(token_a, caller, (funds.amount * 997 * reserve_a) / (reserve_b * 1000 + funds.amount * 997));
    reserve_a = reserve_a - (funds.amount * 997 * reserve_a) / (reserve_b * 1000 + funds.amount * 997);
    reserve_b = reserve_b + funds.amount;
    vault.merge(funds);
    emit Swapped(caller, token_b, funds.amount, min_out);
  }
  event Deposited(who: Q_Address, token: Q_Address, amount: u128);
  event LiquidityAdded(who: Q_Address, amount_a: u128, amount_b: u128, minted: u128);
  event LiquidityRemoved(who: Q_Address, burned: u128);
  event Swapped(who: Q_Address, token_in: Q_Address, amount_in: u128, floor_out: u128);
}
