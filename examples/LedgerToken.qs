contract LedgerToken {
  asset LTK;
  state {
    decimals: u64;
    symbol: u64;
    owner: Q_Address;
    total_supply: u128;
    max_supply: u128 = 1_000_000_000;
  }
  genesis {
    decimals = deploy_params.decimals;
    symbol = deploy_params.symbol;
    owner = deployer;
    total_supply = 0;
  }
  invariant total_supply <= max_supply;
  entry mint(order: MintOrder signed by owner)
    mints LTK
    writes(total_supply)
    limits total_supply + order.amount <= max_supply
  {
    total_supply += order.amount;
    mint_asset(order.to, order.amount);
    emit Minted(order.to, order.amount);
  }
  entry transfer(order: TransferOrder signed by owner) {
    send_asset(self, order.to, order.amount);
    emit Transferred(order.to, order.amount);
  }
  event Minted(to: Q_Address, amount: u128);
  event Transferred(to: Q_Address, amount: u128);
}
