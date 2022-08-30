package chain

import "fmt"

func VerifyIPTablesPath(verify bool) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerIPTables)
		if !ok {
			panic(fmt.Errorf("VerifyIPTablesPath is valid only with iptables chain manager"))
		}

		c.verifyIptablesPath = false
	}
}

func IPTablesPath(path string) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerIPTables)
		if !ok {
			panic(fmt.Errorf("IPTablesPath is valid only with iptables chain manager"))
		}

		c.iptablesPath = path
	}
}

func IP6TablesPath(path string) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerIPTables)
		if !ok {
			panic(fmt.Errorf("IP6TablesPath is valid only with iptables chain manager"))
		}

		c.ip6tablesPath = path
	}
}

func EnableNFTWorkaround(enabele bool) ChainManagerOpt {
	return func(cm ChainManager) {
		c, ok := cm.(*ChainManagerIPTables)
		if !ok {
			panic(fmt.Errorf("EnableNFTWorkaround is valid only with iptables chain manager"))
		}

		c.nftWorkaround = true
	}
}
