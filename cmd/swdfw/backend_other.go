//go:build !linux

package main

import (
	"fmt"
	"runtime"

	"github.com/ZentriaMC/swdfw/chain"
)

func newNFTablesManager(_ string, _ ...chain.ChainManagerOpt) (chain.ChainManager, error) {
	return nil, fmt.Errorf("nftables backend is not available on %s", runtime.GOOS)
}

const hasNFTables = false
