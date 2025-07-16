# IPv6 Tcl Package

This package offers a suite of procedures to simplify the handling of IPv6 addresses within Tcl scripts. It allows for validation, normalization, and various arithmetic and logical operations on IPv6 prefixes. inspired by the `tcllib_ip` package.

---

## Commands

- **ipv6::isIpv6** *IpAddr*
- **ipv6::normalize** *IpAddr*
- **ipv6::suppress** *IpAddr*
- **ipv6::contract** *IpAddr*
- **ipv6::mask** *IpAddr*
- **ipv6::equal** *IpAddr1* *IpAddr2*
- **ipv6::prefix** *IpAddr*
- **ipv6::nextIP** *IpAddr* *?Offset?*
- **ipv6::nextNet** *IPPrefix* *?Offset?*
- **ipv6::isOverlap** *IPPrefix1* *IPPrefix2*
- **ipv6::reduceToAggregates** *PrefixList*
- **ipv6::collapse** *PrefixList*
- **ipv6::subtract** *PosPrefixList* *NegPrefixList*
- **ipv6::expandSubnet** *IPPrefix* *NewMask* ?**-offset?** *count*? ??**-lastNet?** *IPPrefix*? ??**-skip?** *count*?
- **ipv6::ipv6ToEthMulticast** *IpAddrList*

---

### `ipv6::isIpv6 IpAddr`

Checks if the given string is a valid IPv6 address.
Returns `1` for valid, `0` otherwise.

```tcl
% ipv6::isIpv6 ::1/127
1
% ipv6::isIpv6 2002::1g
0
```

### `ipv6::normalize IpAddr`

Converts an IPv6 address into its fully expanded form.

```tcl
% ipv6::normalize ::
0000:0000:0000:0000:0000:0000:0000:0000
% ipv6::normalize 2001:1:2::a/128
2001:0001:0002:0000:0000:0000:0000:000A/128
```

### `ipv6::suppress IpAddr`

Removes leading zeros from each quartet of an IPv6 address.

```tcl
% ipv6::suppress 2001:0001:0002:0000:0000:0000:0000:000A/128
2001:1:2:0:0:0:0:A/128
```

### `ipv6::contract IpAddr`

Converts an IPv6 address into its compact, contracted form using `::`.

```tcl
% ipv6::contract 2002:0000:0000:0001:0000:0000:0000:0002
2002:0:0:1::2
```

### `ipv6::mask IpAddr`

Returns the prefix length of a given IPv6 address. Defaults to 128 if unspecified.

```tcl
% ipv6::mask 2002:0:0:1::2
128
% ipv6::mask 2002:0:0:1::2/64
64
```

### `ipv6::equal IpAddr1 IpAddr2`

Compares two IPv6 network prefixes.
Returns `1` if they match, `0` otherwise.

```tcl
% ipv6::equal 2001::1/64 2001::2/64
1
% ipv6::equal 2001::1 2001::2
0
```

### `ipv6::prefix IpAddr`

Returns the network portion of an IPv6 address.

```tcl
% ipv6::prefix 2002:1234:5678:1234:abcd:effe:dcba:abcd/64
2002:1234:5678:1234::
% ipv6::prefix 2002:1234:5678:1234:abcd:effe:dcba:abcd/32
2002:1234::
```

### `ipv6::nextIP IpAddr ?Offset?`

Calculates the next IPv6 address. Default offset is 1.

```tcl
% ipv6::nextIP ::1
::2
% ipv6::nextIP 2002:abcd::6 4
2002:ABCD::A
```

### `ipv6::nextNet IPPrefix ?Offset?`

Calculates the next network prefix. Default offset is 1.

```tcl
% ipv6::nextNet 2001:1:2:3::a/64
2001:1:2:4::
% ipv6::nextNet 2001:1:2:3::a/64 4
2001:1:2:7::
```

### `ipv6::isOverlap IPPrefix1 IPPrefix2`

Checks if `IPPrefix2` is a subnet of `IPPrefix1`.

```tcl
% ipv6::isOverlap 2001:1234::/32 2001:1234:5678::/64
1
```

### `ipv6::reduceToAggregates PrefixList`

Finds least-specific overlapping prefixes.

```tcl
% ipv6::reduceToAggregates {2002:2222::/32 2002::/16 5000::/4 4000::/2}
2002::/16 4000::/2
```

### `ipv6::collapse PrefixList`

Merges contiguous prefixes into aggregates.

```tcl
% ipv6::collapse {2002:2002::/31 2002:2001::/32 2002:2000::/32 2002:2004::/32 2002:2005::/32}
2002:2000::/30 2002:2004::/31
```

### `ipv6::subtract PosPrefixList NegPrefixList`

Subtracts negative prefixes from a list of positive prefixes.

```tcl
% ipv6::subtract 2002:2000::/30 2002:2000::/32
2002:2002::/31 2002:2001::/32

% ipv6::subtract 2002:2000::/30 {2002:2000::/32 2002:2001::/32}
2002:2002::/31

% ipv6::subtract {2002:2000::/30 2003:2000::/30} {2002:2000::/32 2002:2001::/32 2003:2000::/31}
2003:2002::/31 2002:2002::/31
```

### `ipv6::expandSubnet IPPrefix NewMask ?-offset count? ?-lastNet IPPrefix? ?-skip count?`

Generates a list of subnets from a given IPv6 prefix.

```tcl
% ipv6::expandSubnet 2001:2::/62 64
2001:2::/64 2001:2:0:1::/64 2001:2:0:2::/64 2001:2:0:3::/64

% ipv6::expandSubnet 2001:2::/62 64 -lastNet 2001:2:0:1::/64
2001:2:0:2::/64 2001:2:0:3::/64

% ipv6::expandSubnet 2001:2::/62 64 -skip 2
2001:2:0:2::/64 2001:2:0:3::/64
```

### `ipv6::ipv6ToEthMulticast IpAddrList`

Maps IPv6 multicast addresses to their Ethernet multicast MAC addresses.

```tcl
% ipv6::ipv6ToEthMulticast {ff01::1 ff05::abcd:1234}
333300000001 3333abcd1234
```

---

## Uppercase Command Variants

This package also includes uppercase-named counterparts for several commands:

* `Prefix`, `NextIP`, `NextNet`, `ReduceToAggregates`, `Collapse`, `Subtract`, `ExpandSubnet`

These return results in **normalized (fully expanded)** form instead of compact.
