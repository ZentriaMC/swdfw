# swdfw

SoftWare Defined FireWall

## What?

An approach to define & update iptables rules atomically. No hiccups and easy rollback.

## How?

swdfw manages its rules in a separate chain and uses iptables `--goto` to specify target rule set where to jump to.
All you have to do is allow swdfw to set up jump to its managed output chain (`SWDFW-OUTPUT` by default), or set it up by yourself.

### Replacing rules

TODO: schematic

## Why?

### iptables?

swdfw focses initally on iptables because of [It's 2021: nftables still does not integrate][zentria-iptables-blog-post].
I believe it's better to focus on iptables initially to support wide variety of software out of the box.

[nftables][nftables] support is planned in the future, mainly because Zentria infrastructure uses nftables in some places already.

### Existing solutions on infrastructure level

It's common to disable OS level firewall on cloud providers when provider has its own firewall solution available.
However, it appears that some of the providers do not have reasonable firewall (or alternatively named security groups) support.

1) Hetzner Robot allows only maximum of 10 incoming rules
2) ...

### Changing rules dynamically

Wiring machines together dynamically using automation (etcd, Consul etc.) means that it's not very convenient to pull
the strings on the provider side. Some providers (AWS) take about a minute in my experience (using Terraform) to apply the rules,
causing slow configuration rollout.

With swdfw, applying a new set of rules is as fast as machine can swap out the rules.


## Roadmap

- [x] Proof of concept output rules generation + integration test
- [ ] Output rules
- [ ] Tunables
    - [ ] Default INPUT/OUTPUT policy handling
    - [ ] DROP instead of REJECT
    - [ ] Collecting rules targeting same CIDR with different ports into [multiport match][iptables-extensions-multiport]
- [ ] [ipset][ipset] support
- [ ] [nftables][nftables] support

## License

Not determined yet.

[zentria-iptables-blog-post]: https://blog.zentria.company/posts/its-2021-nftables-still-does-not-integrate/
[iptables-extensions-multiport]: https://ipset.netfilter.org/iptables-extensions.man.html#lbBM
[ipset]: https://ipset.netfilter.org/ipset.man.html
[nftables]: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
