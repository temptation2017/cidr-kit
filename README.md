# cidr-kit

零依赖 Python CLI：查看网段信息，判断包含和重叠，拆分、汇总、从网段中挖洞。支持 IPv4 和 IPv6。

## 做什么

写防火墙、对路由、划 VPC 或核对访问名单时，经常要算「这个地址在不在这段里」「两段有没有交叉」「挖掉一段还剩什么」。`cidr-kit` 只做这些本地计算，不连网、无第三方依赖。

| 子命令 | 作用 | 例子 |
|--------|------|------|
| **info** | 网络地址、掩码、广播、可用主机、标志 | `192.0.2.15/24` → 所属 `192.0.2.0/24`，254 个可用主机 |
| **contains** | 网段是否包含另一个 IP / 网段 | `10.0.0.0/8` 包含 `10.1.2.3` → yes |
| **overlap** | 两段是否相交 | `10.0.0.0/16` 与 `10.1.0.0/16` → no |
| **split** | 拆成更长（更细）的前缀 | `192.0.2.0/24` 拆成 `/26` → 4 段 |
| **summarize** | 合并相邻或重叠的网段 | 两个 `/25` → 一个 `/24` |
| **exclude** | 从网段中挖掉一段或多段 | `/24` 挖掉中间一个 `/26` → `/26` + `/25` |

所有输入既可以是 CIDR（`192.0.2.0/24`），也可以是单地址（按 `/32` 或 `/128` 处理）。带主机位的写法（`192.0.2.15/24`）会归到覆盖它的网段。

## 要求

- Python 3.8+
- 标准库 only（`ipaddress` / `argparse` / `json`）

## 用法

```bash
# 查看网段详情（输入带主机位时会注明）
python3 cidr_kit.py info 192.0.2.15/24
python3 cidr_kit.py info 2001:db8::/32

# 判断包含 / 重叠（是则退出码 0，否则 1，便于脚本）
python3 cidr_kit.py contains 10.0.0.0/8 10.1.2.3
python3 cidr_kit.py overlap 10.0.0.0/16 10.0.128.0/17

# 拆分、汇总、挖洞
python3 cidr_kit.py split 192.0.2.0/24 26
python3 cidr_kit.py summarize 192.0.2.0/25 192.0.2.128/25
python3 cidr_kit.py summarize -f examples.txt
cat examples.txt | python3 cidr_kit.py summarize
python3 cidr_kit.py exclude 192.0.2.0/24 192.0.2.64/26

# 机器可读输出
python3 cidr_kit.py --json info 192.0.2.0/24
python3 cidr_kit.py --json exclude 192.0.2.0/24 192.0.2.64/26
```

仓库自带 `examples.txt`，用的是 RFC 5737 / RFC 3849 文档地址（TEST-NET 与 `2001:db8::/32`），没有真实网络或个人信息。`summarize` 从文件或 stdin 读取时，空行和 `#` 注释会被忽略；IPv4 与 IPv6 会按地址族分别合并。

## 退出码

| 码 | 含义 |
|----|------|
| 0 | 成功。`contains` / `overlap` 表示「是」 |
| 1 | `contains` / `overlap` 表示「否」（stdout 仍会打印 `no` 或 JSON） |
| 2 | 用法错误、地址非法、混用地址族（除 `summarize` 外）、拆分数量超限等（详情在 stderr） |

## 规则

- `info` 的 IPv4 可用主机数：`/32` 为 1，`/31` 为 2（RFC 3021），更短前缀排除网络地址和广播地址
- IPv6 没有广播，`info` 给出前缀内的首尾地址，不提供「可用主机」计数
- 两个 CIDR 若相交，必然是一段包含另一段；`overlap` 对相邻但不重叠的网段返回 `no`
- `split` 只允许拆成更长或相同的前缀；一次最多输出 4096 段，避免把 `/8` 拆成 `/24` 撑满终端
- `summarize` 使用标准库 `collapse_addresses`：只有对齐的相邻前缀才会合并（例如 `2001:db8::/48` 与 `2001:db8:1::/48` 合成 `2001:db8::/47`，但 `…:1::/48` 与 `…:2::/48` 不会）
- `exclude` 可挖多个洞，输出覆盖剩余地址的最少 CIDR 列表；全部挖空则打印空（JSON 为 `[]`），退出码仍为 0
- `Flags` 来自 Python `ipaddress`（private / global / multicast 等），另外会标记 RFC 文档地址。当前解释器里 TEST-NET 也会带 `private`

## 示例

`python3 cidr_kit.py info 192.0.2.15/24`：

```
Input:            192.0.2.15/24
Family:           IPv4
Address:          192.0.2.15
CIDR:             192.0.2.0/24
Network:          192.0.2.0
Prefix length:    24
Netmask:          255.255.255.0
Wildcard:         0.0.0.255
Broadcast:        192.0.2.255
First host:       192.0.2.1
Last host:        192.0.2.254
Total addresses:  256
Usable hosts:     254
PTR:              15.2.0.192.in-addr.arpa
Flags:            private, documentation
Note:             input had host bits set; CIDR is the covering network
```

`python3 cidr_kit.py exclude 192.0.2.0/24 192.0.2.64/26`：

```
192.0.2.0/26
192.0.2.128/25
```

`python3 cidr_kit.py summarize -f examples.txt`：

```
192.0.2.0/24
198.51.100.0/24
203.0.113.0/24
2001:db8::/47
```

自测：`python3 -m unittest test_cidr_kit.py`

## 限制与后续可改进点

- 只做本地地址计算，不查询 DNS、WHOIS 或路由表；`PTR` 只是按规则反写，不会发起查询
- 不接受 `10.0.0.10-10.0.0.40` 这种起止范围，也不接受通配掩码（`10.0.0.0 0.0.0.255`）写法
- 没有 ASN、地理位置或前缀树可视化
- 若需要，后续可以加上范围 → CIDR 转换，以及通配掩码输入

## License

[MIT](LICENSE)
