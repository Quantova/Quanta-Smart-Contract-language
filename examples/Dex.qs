contract Dex {
  state {
    operator: Q_Address;
    token_a: Q_Address;
    token_b: Q_Address;
    vault_a: Q_Asset<TOKA>;
    vault_b: Q_Asset<TOKB>;
  }
  genesis {
    operator = deploy_params.operator;
    token_a = deploy_params.token_a;
    token_b = deploy_params.token_b;
  }
  entry swap_a_for_b(funds: Q_Asset<TOKA>, order: sealed SwapOrder signed by operator)
    reads(token_a, token_b)
    writes(vault_a)
    conserves TOKA
  {
    guard in_asset == token_a;
    guard funds.amount == order.amount_in;
    vault_a.merge(funds);
    send_asset(token_b, order.to, order.out);
    emit Swapped(order.to, order.out);
  }
  entry swap_b_for_a(funds: Q_Asset<TOKB>, order: sealed SwapOrder signed by operator)
    reads(token_a, token_b)
    writes(vault_b)
    conserves TOKB
  {
    guard in_asset == token_b;
    guard funds.amount == order.amount_in;
    vault_b.merge(funds);
    send_asset(token_a, order.to, order.out);
    emit Swapped(order.to, order.out);
  }
  event Swapped(to: Q_Address, amount: u128);
}
