//go:build linux

package chain

import (
	"fmt"

	"github.com/google/nftables"
)

// WithTableName sets the nftables table name (default: "swdfw").
func WithTableName(name string) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerNFTables)
		if !ok {
			panic(fmt.Errorf("WithTableName is valid only with nftables chain manager"))
		}

		c.tableName = name
	}
}

// WithNFTConn sets a custom nftables connection (useful for testing).
func WithNFTConn(conn *nftables.Conn) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerNFTables)
		if !ok {
			panic(fmt.Errorf("WithNFTConn is valid only with nftables chain manager"))
		}

		c.conn = conn
	}
}

