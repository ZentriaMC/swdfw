package chain

type Quirk int

const (
	// When iptables-nft is used, then `iptables -S <chain 1` is broken on non-existent chain
	QuirkIPTablesBrokenChainCheck Quirk = iota
)

func Quirks(quirks ...Quirk) ChainManagerOpt {
	return func(c ChainManager) {
		c.(chainManagerBaseGetter).Mut(func(cm *chainManagerBase) {
			for k := range cm.quirks {
				delete(cm.quirks, k)
			}

			for _, q := range quirks {
				cm.quirks[q] = true
			}
		})
	}
}
