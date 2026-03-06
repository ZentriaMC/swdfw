package chain

import "fmt"

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
