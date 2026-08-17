contract Dex {
  state {
    operator: Q_Address;
    token_a: Q_Address;
    token_b: Q_Address;
  }
  genesis {
    operator = deploy_params.operator;
    token_a = deploy_params.token_a;
    token_b = deploy_params.token_b;
  }
  entry swap_a_for_b(order: sealed SwapOrder signed by operator) {
    send_asset(token_b, order.to, order.out);
    emit Swapped(order.to, order.out);
  }
  entry swap_b_for_a(order: sealed SwapOrder signed by operator) {
    send_asset(token_a, order.to, order.out);
    emit Swapped(order.to, order.out);
  }
  event Swapped(to: Q_Address, amount: u128);
}
