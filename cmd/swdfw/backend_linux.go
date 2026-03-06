package main

import "github.com/ZentriaMC/swdfw/chain"

func newNFTablesManager(table string, opts ...chain.ChainManagerOpt) (chain.ChainManager, error) {
	opts = append(opts, chain.WithTableName(table), chain.WithAutoApply(false))
	return chain.NewNFTablesManager(opts...)
}

const hasNFTables = true
