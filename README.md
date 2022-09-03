# swdfw

SoftWare Defined FireWall

## What?

An approach to define & update iptables rules atomically. No hiccups and easy rollback.

## How?

swdfw manages its rules in a separate chain and uses iptables `--goto` to specify target rule set where to jump to.
All you have to do is allow swdfw to set up jump to its managed input & output chains (`SWDFW-INPUT` & `SWDFW-OUTPUT` by default), or set them up by yourself.

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
- [ ] Rules covering all protocols or only handling interfaces
- [ ] Rules declaration (file format/structure)
- [ ] Try to retain script generation support
    - [ ] Works fine-ish with iptables already, but nftables might be a problem.
- [ ] Tunables
    - [ ] Default INPUT/OUTPUT policy handling
    - [ ] DROP instead of REJECT
    - [ ] Collecting rules targeting same CIDR with different ports into [multiport match][iptables-extensions-multiport]
    - [ ] Collecting rules targeting different CIDRs with same ports into [ipset][ipset]
- [ ] [ipset][ipset] support
- [ ] [nftables][nftables] support
    - [ ] Could utilize [JSON input/output][redhat-nftables-json] support

## Known issues

- [ ] Limits are not documented
    - iptables chain name length is strictly 28. Current update logic needs reserving 6 characters (could do less).
    - nftables allows for longer, tested with 70 character name.
    - Therefore allow only 16-24 character names for rulesets?
- [ ] [TOCTOU][toctou]
    - Need locking mechanism between swdfw instances working on same set of rules.

## License

Not determined yet.

[zentria-iptables-blog-post]: https://blog.zentria.company/posts/its-2021-nftables-still-does-not-integrate/
[iptables-extensions-multiport]: https://ipset.netfilter.org/iptables-extensions.man.html#lbBM
[ipset]: https://ipset.netfilter.org/ipset.man.html
[nftables]: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
[redhat-nftables-json]: https://web.archive.org/web/20211026094902/https://workshop.netfilter.org/2019/wiki/images/c/c6/NFWS_2019_-_firewalld%2C_libnftables%2C_and_json%2C_oh_my.pdf
[toctou]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
