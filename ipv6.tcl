#	 Copyright (C) 2017 David Nishnianidze d_nishnianidze@yahoo.com. All Rights Reserved. 
#	
#	Redistribution and use in source and binary forms, with or without
#	modification, are permitted provided that the following conditions are met:
#	
#	  a. Redistributions of source code must retain the above copyright notice,
#	     this list of conditions and the following disclaimer.
#	  b. Redistributions in binary form must reproduce the above copyright
#	     notice, this list of conditions and the following disclaimer in the
#	     documentation and/or other materials provided with the distribution.
#	
#	
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#	ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
#	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#	SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#	CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#	LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#	OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#	DAMAGE.



# ################ #
#     FUNCTIONS    #
# ################ #
#
# isIpv6
# normilize
# suppress
# compress
# mask
# equal
# prefix
# nextIP
# nextNet
# isOverlap
# reduceToAggregates
# collapse
# subtract
# expandSubnet
# ipv6ToEthMulticast

package provide ipv6 1.0

namespace eval ipv6 {
	#
	namespace export isIpv6 normilize suppress compress mask equal prefix Prefix nextIP NextIP nextNet NextNet isOverlap reduceToAggregates ReduceToAggregates collapse Collapse subtract Subtract expandSubnet ExpandSubnet ipv6ToEthMulticast
	#
	variable NBBL_CHAR_LENGTH 4
	variable HEX_BIT_LENGTH 4
	variable PREFIX_LENGTH_MIN 0
	variable PREFIX_LENGTH_MAX 128
	variable IP_ADDR_CHAR_LENGTH 32
	variable IP_ADDR_NBBL_LENGTH 8
	variable IP_ADDR_BIT_LENGTH 128
	#
	variable IPV6_MULTICAST_PREFIX FF00::
	variable EHT_IPV6_MUL_FIRST_4_HEX_CHAR 3333

	
	proc GetMask {Mask} {
		variable IP_ADDR_BIT_LENGTH
		#
		if {$Mask eq {}} {
			return 0
		} else {
			return [expr {$IP_ADDR_BIT_LENGTH - $Mask}]
		}
	}


	#add to hex string
	proc AddToHex {Hex Offset} {
		#
		set IPv6Dec [expr {[join "0x $Hex" {}] + $Offset}]
		#
		if {$IPv6Dec < 0} {
			return -code error [concat IPv6 address can't be less than 0]
		}
		#
		return $IPv6Dec
	}


	# check syntax of ipv6 addres (length, characters)
	# 
	# Input  - ipv6 addres prefix with mask (::/64)
	#
	# Return - list IPv6 addres in hex string and mask (0-128)
	proc IPtoHexAndGetMask {IPPrefix} {
		lassign [SplitIPMask $IPPrefix] IpAddr_tmp Mask
		#
		set Mask [GetMask $Mask]
		#
		try {
			set IpAddr_tmp [IPtoHexString [normilize $IpAddr_tmp]]
		} on error {result options} {
			return -code error $result
		}
		#
		return [list $IpAddr_tmp $Mask]
	}


	#convert decimal value to hex
	proc DecToHex {DecValue} {
		return [format %llx $DecValue]
	}


	# convert hex string to ipv6 address format
	# 
	# Input  - Hex string (32 chars)
	#
	# Return - IPv6 addres in expanded format
	proc HexStringToIP {HexString} {
		variable NBBL_CHAR_LENGTH
		variable IP_ADDR_CHAR_LENGTH
		#
		set IpAddr_tmp {}
		#
		for {set i 0} {$i < $IP_ADDR_CHAR_LENGTH} {incr i 4} {
			set IpAddr_tmp [join [concat $IpAddr_tmp [string range $HexString $i [expr {$i + $NBBL_CHAR_LENGTH - 1}]]] :]
		}
		#
		return [string toupper $IpAddr_tmp]
	}


	#converts decimal value to ipv6 address format
	proc DecToIP {DecValue} {
		#convert decimal value to hex string and fills with zeros if needed
		set IpAddr_tmp [FillZeros [DecToHex $DecValue]]
		#
		return [HexStringToIP $IpAddr_tmp]
	}


	# fill hex string with leading 0s
	# 
	# Input  - Hex string (chars 0-32)
	#
	# Return - IPv6 hex string (32 chars) 
	proc FillZeros {HexString} {
		variable IP_ADDR_CHAR_LENGTH
		#
		set HexString_tmp $HexString
		#
		if {[string length $HexString] < $IP_ADDR_CHAR_LENGTH} {
			set CharDiff [expr {$IP_ADDR_CHAR_LENGTH - [string length $HexString]}]
			set HexString_tmp [join [concat [string repeat 0 $CharDiff] $HexString] {}]
		}
		#
		return $HexString_tmp
	}


	#
	proc NormTo4BitBound {IPHexString {Mask 0}} {
		variable HEX_BIT_LENGTH
		#
		set Mod [expr {$Mask % $HEX_BIT_LENGTH}]
		#
		set Dec [expr {[join "0x $IPHexString" {}] << $Mod}]
		#
		return [DecToHex $Dec]
	}


	#
	proc ShiftBitsRight {IPHexString {Mask 0}} {
		set Dec [expr {[join "0x $IPHexString" {}] >> $Mask}]
		#
		return $Dec
	}


	#
	proc ShiftBitsLeft {IPHexString {Mask 0}} {
		set Dec [expr {[join "0x $IPHexString" {}] << $Mask}]
		#
		return $Dec
	}	
	
	
	# Check input prefixes and expand if needed
	# 
	# Input  - List of ipv6 prefixes with or without prefix length (aa::a/64 bb:: :: ...)
	#
	# Return - List of expanded ipv6 prefixes with mask
	proc CheckAndNormilize {PrefixList} {
		try {
			foreach Prefix $PrefixList {
				lappend Tmp [Prefix $Prefix]/[mask $Prefix]
			}
			#
			return $Tmp
		} on error {result options} {
			return -code error $result
		}
	}


	#Remove item from list
	proc Lpop {List Item} {
		set ItemId [lsearch $List $Item]
		#
		return [lreplace $List $ItemId $ItemId]
	}

	
	# Compare prefix length of prefixes, used in lsort -command
	# 
	# Input  - ipv6 prefixes with or without prefix length (aa::a/64 bb:: :: ...)
	#
	# Return - compare result
	proc SortLargeToSmallMask {Prefix1 Prefix2} {
		return [expr {([string compare [mask $Prefix1] [mask $Prefix2]])}]
	}


	# converts ipv6 hex string to network portion hex string
	# 
	# Input  - ipv6 hex string (32 chars), network prefix length
	#
	# Return - network portion hex string
	proc HexStringToNetBits {IPHexString {Mask 0}} {
		set IpAddr_tmp [ShiftBitsRight $IPHexString $Mask]
		#
		return [DecToHex $IpAddr_tmp]
	}


	# IPHexString - ipv6 hex string without colons
	# Mask   - prefix length (0 - 128)
	#
	# Return - ipv6 network string without colons
	proc PrefixToNet {IPHexString {Mask 0}} {
		set IpAddr_tmp [DecToHex [ShiftBitsRight $IPHexString $Mask]]
		#
		return [DecToHex [ShiftBitsLeft $IpAddr_tmp $Mask]]
	}

	#
	proc WithMask {IpAddr {Mask {}}} {
		set IpAddr_tmp $IpAddr
		#
		if {$Mask ne ""} {
			set IpAddr_tmp [join [list $IpAddr $Mask] /]
		}
		#
		return $IpAddr_tmp
	}


	# Return - ipv6 address string without colons
	#
	# IpAddr - ipv6 address
	proc IPtoHexString {IpAddr} {
		return [join [split $IpAddr :] {}]
	}

	# Check prefix length range
	#
	# IPPrefix - ipv6 address and mask(if specified) (::/64)
	#
	# Return - ipv6 address and prefix length (0-128)
	proc SplitIPMask {IPPrefix} {
		variable PREFIX_LENGTH_MIN
		variable PREFIX_LENGTH_MAX
		#
		set IpAddr_tmp [split $IPPrefix /]
		#
		if {[llength $IpAddr_tmp] == 2} {
			set Mask [lindex $IpAddr_tmp 1]
			#check mask
			if [string is int $Mask] {
				#check mask range 
				if {$Mask >= $PREFIX_LENGTH_MIN && $Mask <= $PREFIX_LENGTH_MAX} {
					return $IpAddr_tmp
				}
			}
			#
			return -code error [list Invalid Prefix Length]
		}
		#
		return $IPPrefix
	}


	# Return - list of ipv6 address string before and after double colon
	#
	# IpAddr - ipv6 address
	proc SplitIPColon {IpAddr} {
		#match double colon in ipv6 address
		regexp {(.*)::(.*)} $IpAddr -> Prefix Sufix
		#
		if {$Prefix eq ""}  {set Prefix 0}
		if {$Sufix  eq ""}  {set Sufix 0}
		#
		return [list $Prefix $Sufix]
	}


	# Return - number of double colons in ipv6 address
	#
	# IpAddr - ipv6 address
	proc CheckDoubleColon {IpAddr} {
		return [llength [regexp -inline -all {::} $IpAddr]]
	}


	# check syntax of ipv6 addres (char length)
	#
	# IpAddr - ipv6 address
	# DoubleColon - is double colon in ipv6 address 
	#
	# Return - 0 Valid or 1 Invalid
	proc CheckLength {IpAddr DoubleColon} {
		variable IP_ADDR_NBBL_LENGTH
		#
		set ErrorStatus 0
		set Addr       [split $IpAddr :]
		set AddrLength [llength $Addr]
		#check ip nibble sum
		if {!$ErrorStatus && $AddrLength > $IP_ADDR_NBBL_LENGTH} {
			set ErrorStatus 1
		}
		#check if ip address nibble sum < 8 and it does not have double colon
		if {!$ErrorStatus && $AddrLength != $IP_ADDR_NBBL_LENGTH && $DoubleColon != 1} {
			set ErrorStatus 1
		}	
		#check ip address nibble length (should not be more than 4)
		if {!$ErrorStatus} {
			foreach Nibble $Addr {
				set NibbleCharLength [string length $Nibble]
				if {$NibbleCharLength > 4} {
					set ErrorStatus 1
					break
				}
			}
		}
		#
		return $ErrorStatus
	}


	# Check ipv6 address syntax
	#
	# IpAddr - ipv6 address with or without mask
	#
	# Return - 1 Valid or 0 Invalid
	proc  isIv6 {IpAddr} {
		set ErrorStatus 0
		set DoubleColon 0
		set Result 1
		#check mask if specified
		lassign [SplitIPMask $IpAddr] Addr Mask
		#check if ipaddress starts or ends with one colon
		if {!$ErrorStatus && [regexp {(^:[^:]|[^:]:$)} $Addr]} {
			set ErrorStatus 1
			set Result      "Unbalanced colon $Addr"
		}
		#match every char in ipv6 except legits (a-f A-F : digit)
		if {!$ErrorStatus && [regexp -nocase {[^\da-f:]} $Addr]} {
			set ErrorStatus 1
			set Result      "Illegal syntax $Addr"
		}
		#check if ip address contains less than 2 double colons
		if {!$ErrorStatus} {
			set DoubleColon [CheckDoubleColon $Addr]
			#
			switch -- $DoubleColon {
				0 {}
				1 {set Addr [join [SplitIPColon $Addr] :]}
				default {
					set ErrorStatus 1
					set Result "Unbalanced colon $Addr"
				}
			}
		}
		#check ipv6 address length
		if {!$ErrorStatus} {
			set ErrorStatus [CheckLength $Addr $DoubleColon]
			#
			if $ErrorStatus {
				set Result "Invalid length $Addr"
			}
		}
		#
		return -code $ErrorStatus $Result
	}


	# expand ipv6 address syntax without leading zeros (aa:: -> AA:0:0:0:0:0:0:0)
	#
	# IpAddr - ipv6 address without mask
	#
	# Return - full ipv6 address
	proc Expand {IpAddr} {
		variable IP_ADDR_NBBL_LENGTH 
		#check if ipv6 address has legitimate syntax
		if [isIpv6 $IpAddr] {
			set IpAddr_tmp $IpAddr
			#check if address has double colon
			set DoubleColon [CheckDoubleColon $IpAddr]
			#expand ip address
			if {$DoubleColon == 1} {
				lassign [SplitIPColon $IpAddr] Prefix Sufix
				#calculate how many nibbles are suppressed
				set NibbleLength(Prefix)  [llength [split $Prefix  :]]
				set NibbleLength(Sufix) [llength [split $Sufix :]]
				set NibbleSum  [expr {$NibbleLength(Prefix) + $NibbleLength(Sufix)}]
				set NibbleDiff [expr {$IP_ADDR_NBBL_LENGTH  - $NibbleSum}]
				#append suppressed nibbles with 0-s
				set IpAddr_tmp [join [list $Prefix {*}[lrepeat $NibbleDiff 0] $Sufix] :]
			}
			return [string toupper $IpAddr_tmp]
		}
		return -code error [list something went wrong]
	}
	
	
	# Expand ipv6 address to it's full syntax  (aa:: -> 00AA:0000:0000:0000:0000:0000:0000:0000)
	# 
	# IpAddr - ipv6 address with or without mask
	#
	#Return - full ipv6 address with leading 0
	proc normilize {IpAddr} {
		variable NBBL_CHAR_LENGTH
		#
		lassign [SplitIPMask $IpAddr] Addr Mask
		#
		set IpAddrExp [Expand $Addr]
		#
		set IpAddr_tmp {}
		#
		foreach Nibble [split $IpAddrExp :] {
			set NibbleCharLength [string length $Nibble]
			#append nibble leading zeros
			set Nibble [join [concat [string repeat 0 [expr {$NBBL_CHAR_LENGTH - $NibbleCharLength}]] $Nibble] {}]
			set IpAddr_tmp [join [concat $IpAddr_tmp $Nibble] :]
		}
		#
		return [WithMask $IpAddr_tmp $Mask]
	}


	# Remove leading zeros (00AA:0000:0000:0000:0000:0000:0000:0000 -> AA:0:0:0:0:0:0:0)
	#
	# IpAddr - ipv6 address with or without mask
	#
	# Return - suppressed ipv6 address
	proc suppress {IpAddr} {
		variable IP_ADDR_NBBL_LENGTH
		variable NBBL_CHAR_LENGTH
		#
		lassign [SplitIPMask $IpAddr] Addr Mask
		#
		set IpNormAddr [normilize $Addr]
		#
		set IpAddr_tmp {}
		#
		foreach Nibble [split $IpNormAddr :] {
			if {$Nibble ne "0000"} {
				set Nibble [string trimleft $Nibble 0]
			} else {
				set Nibble 0
			}
			#
			set IpAddr_tmp [join [concat $IpAddr_tmp $Nibble] :]
		}
		#
		return [WithMask $IpAddr_tmp $Mask]
	}


	# Remove continuous zeros to double colon and remove leading zeros (0AA0:0000:0000:0000:0000:0000:0000:0000/64 -> AA0::/64)
	# 
	# IpAddr - ipv6 address with or without mask
	#
	# Return - compressed ipv6 address
	proc compress {IpAddr} {
		#
		lassign [SplitIPMask $IpAddr] Addr Mask
		#
		set IpSupAddr  [suppress $Addr]
		set SplitIP    [split $IpSupAddr :]
		#
		set IpAddr_tmp $IpSupAddr
		set StartZeroIndx 0
		set NibblePosition 0
		set NewSeq 1
		#
		foreach Nibble $SplitIP {
			if {$Nibble eq "0" && $NewSeq == 1} {
				incr ZeroLength($NibblePosition)
				set  StartZeroIndx $NibblePosition
				set  NewSeq 0
			} elseif {$Nibble eq "0" && $NewSeq == 0} {
				incr ZeroLength($StartZeroIndx)
			} else {
				set NewSeq 1
			}
			#
			incr NibblePosition
		}
		#
		if [info exists ZeroLength] {
			if {[llength [array names ZeroLength]] > 1} {
				foreach Indx [lsort [array names ZeroLength]] {
					if ![info exists LargestIndx] {
						set LargestIndx $Indx
					} else {
						set OldValue $ZeroLength($LargestIndx)
						set NewValue $ZeroLength($Indx)
						#
						if {$NewValue > $OldValue} {
							set LargestIndx $Indx
						}
					}
				}
			} else {
				set LargestIndx [array names ZeroLength]
			}
			#
			set Prefix [join [concat [lrange $SplitIP 0 [expr {$LargestIndx - 1}]]] :]
			set Sufix  [join [concat [lrange $SplitIP [expr {$LargestIndx + $ZeroLength($LargestIndx)}] end]] :]
			set IpAddr_tmp [join [list $Prefix $Sufix] ::]
		}
		#
		return [WithMask $IpAddr_tmp $Mask]	
	}


	# Return prefix length from given prefix 
	proc mask {IPPrefix} {
		lassign [SplitIPMask $IPPrefix] IpAddr_tmp Mask
		#
		if {$Mask eq ""} {set Mask 128}
		#
		return $Mask
	} 

	# Compares IPv6 prefixes to each other
	# 
	# IpAddr1 - ipv6 address with or without mask
	# IpAddr2 - ipv6 address with or without mask
	#
	# Return  - 1 if equal else 0
	proc equal {IpAddr1 IpAddr2} {
		#
		try {
			lassign [IPtoHexAndGetMask $IpAddr1] IpAddr_tmp(ip1) IpAddr_tmp(mask1)
			lassign [IPtoHexAndGetMask $IpAddr2] IpAddr_tmp(ip2) IpAddr_tmp(mask2)
		} on error {result options} {
			return -code error $result
		}
		#
		set IpAddr_tmp(ip1) [PrefixToNet $IpAddr_tmp(ip1) $IpAddr_tmp(mask1)]
		set IpAddr_tmp(ip2) [PrefixToNet $IpAddr_tmp(ip2) $IpAddr_tmp(mask2)]
		#
		if {$IpAddr_tmp(ip1) eq $IpAddr_tmp(ip2)} {
			return 1
		} else {
			return 0
		}
	}


	#
	proc Prefix {IPPrefix} {
		try {
			lassign [IPtoHexAndGetMask $IPPrefix] IpAddr_tmp Mask
			#
			set IpAddr_tmp [HexStringToIP [FillZeros [PrefixToNet $IpAddr_tmp $Mask]]]
		} on error {result options} {
			return -code error $result
		}
		return $IpAddr_tmp
	}

	
	#
	proc prefix {IPPrefix} {
		try {
			set Prefix [compress [Prefix $IPPrefix]]
		} on error {result options} {
			return -code error $result
		}
		#
		return $Prefix
	}


	# Calculate new ipv6 addres by given ipv6 address and offset
	# 
	# IpAddr - ipv6 address without mask
	# Offset - Integer to add to provided ipv6 address (can be negative number)
	#
	# Return  - IPv6 address in expanded format
	proc NextIP {IpAddr {Offset 1}} {
		if ![string is int $Offset] {return -code error [concat Error Offset should be integer]}
		#
		try {
			#convert ipv6 addres to hex string
			set IpAddr_tmp [IPtoHexString [normilize $IpAddr]]
			#add offset to ip address
			set IpAddr_tmp [AddToHex $IpAddr_tmp $Offset]
			#convert decimal value to ipv6 syntax
			return [DecToIP $IpAddr_tmp]
		} on error {result options} {
			return -code error $result
		}
	}


	# Calculate new ipv6 addres by given ipv6 address and offset
	# 
	# IpAddr - ipv6 address without mask
	# Offset - Integer to add to provided ipv6 address (can be negative number)
	#
	# Return  - IPv6 address in compact format
	proc nextIP {IpAddr {Offset 1}} {
		try {
			set IpAddr_tmp [compress [NextIP $IpAddr $Offset]]
		} on error {result options} {
			return -code error $result
		}
		#
		return $IpAddr_tmp	
	}

	
	# Calculate new ipv6 prefix by given ipv6 address mask(optional) and offset
	# 
	# IPPrefix - ipv6 address with or without mask
	# Offset   - Integer to add to provided ipv6 address (can be negative number)
	#
	# Return   - IPv6 address in expanded format without mask
	proc NextNet {IPPrefix {Offset 1}} {
		try {
			lassign [IPtoHexAndGetMask $IPPrefix] IpAddr_tmp mask
			#
			set IpAddr_tmp [HexStringToNetBits $IpAddr_tmp $mask]
			#add offset to ip address
			set IpAddr_tmp [DecToHex [AddToHex $IpAddr_tmp $Offset]]
			#convert decimal value to ip syntax
			set IpAddr_tmp [DecToIP [ShiftBitsLeft $IpAddr_tmp $mask]]
			#
			return $IpAddr_tmp
		} on error {result options} {
			return -code error $result
		}
	}

	
	# Calculate new ipv6 prefix by given ipv6 address mask(optional) and offset
	# 
	# IPPrefix - ipv6 address with or without mask
	# Offset   - Integer to add to provided ipv6 address (can be negative number)
	#
	# Return   - IPv6 address in compact format without mask
	proc nextNet {IPPrefix {Offset 1}} {
		try {
			set IpAddr_tmp [compress [NextNet $IPPrefix $Offset]]
		} on error {result options} {
			return -code error $result
		}
		#
		return $IpAddr_tmp	
	}

	
	# Checks if second prefix overlaps with the first one
	#
	# IPPrefix1 - ipv6 address with or without mask
	# IPPrefix2 - ipv6 address with or without mask
	#
	# Return    - 1 if second prefix overlaps with first, 0 if not
	proc isOverlap {IPPrefix1 IPPrefix2} {
		try {
			lassign [IPtoHexAndGetMask $IPPrefix1] IpAddr_tmp(ip1) IpAddr_tmp(mask1)
			lassign [IPtoHexAndGetMask $IPPrefix2] IpAddr_tmp(ip2) IpAddr_tmp(mask2)
			#
			if {$IpAddr_tmp(mask1) < $IpAddr_tmp(mask2)} {
				return 0
			}
			#
			set IpAddr_tmp(ip1) [NormTo4BitBound [HexStringToNetBits $IpAddr_tmp(ip1) $IpAddr_tmp(mask1)] $IpAddr_tmp(mask1)]
			set IpAddr_tmp(ip2) [NormTo4BitBound [HexStringToNetBits $IpAddr_tmp(ip2) $IpAddr_tmp(mask1)] $IpAddr_tmp(mask1)]
			#
			return [expr {$IpAddr_tmp(ip1) eq $IpAddr_tmp(ip2) ? 1:0}]
		} on error {result options} {
			return -code error $result
		}
	}

	
	# Given list of ipv6 prefixes this commands checks if addresses overlap and returns addresses with lower prefix length
	#
	# PrefixList - list of ipv6 prefixes with or without mask
	#
	# Return     - list of ipv6 aggregate addreses
	proc ReduceToAggregates {PrefixList} {
		set ListSize [llength $PrefixList]
		#
		if !$ListSize {return}
		#
		set BREAK            0
		set AggRes           {}
		array set Skip       {}
		array set Matched    {}
		array set Unmatched  {}
		set StartIndx        1
		set MatchedItemIndex NULL
		set SkipItemIndex    NULL
		#
		for {set ListItemIndex 0} {$ListItemIndex < $ListSize} {incr ListItemIndex} {
			#
			if [info exists Skip($ListItemIndex)] {continue}
			#
			set Item1 [lindex $PrefixList $ListItemIndex]
			#
			set MatchedItemIndex NULL
			#
			for {set CompItemIndx $StartIndx} {$CompItemIndx < $ListSize} {incr CompItemIndx} {
				set SkipItemIndex    NULL
				set BREAK 0
				set Item2 [lindex $PrefixList $CompItemIndx]
				#
				if [isOverlap $Item1 $Item2] {
					set MatchedItemIndex $ListItemIndex
					set SkipItemIndex    $CompItemIndx
				} elseif [isOverlap $Item2 $Item1] {
					set MatchedItemIndex $CompItemIndx
					set SkipItemIndex    $ListItemIndex
					set BREAK            1
				}
				#
				if {$SkipItemIndex ne "NULL"    && ![info exists Skip($SkipItemIndex)]} {
					set Skip($SkipItemIndex) 1
				}
				#
				if $BREAK {break}
			}
			#
			if {$MatchedItemIndex ne "NULL" && ![info exists Matched($MatchedItemIndex)]} {
				set Item [lindex $PrefixList $MatchedItemIndex]
				#
				lappend AggRes [list [normilize [prefix $Item]]/[mask $Item]]
				set Matched($MatchedItemIndex) 1				
			}
			#
			if {![info exists Matched($ListItemIndex)] && ![info exists Skip($SkipItemIndex)]} {
				set Unmatched($ListItemIndex) 1
			}
			#
			incr StartIndx
		}
		#
		foreach ListItemIndex [array names Unmatched] {
			set Item [lindex $PrefixList $ListItemIndex]
			lappend AggRes [list [normilize [prefix $Item]]/[mask $Item]]
		}
		#
		return $AggRes
	}

	
	# same as ReduceToAggregates but returns ipv6 prefixes in compact format
	proc reduceToAggregates {PrefixList} {
		foreach Prefix [ReduceToAggregates $PrefixList] {
			lappend PrefixList_tmp [compress $Prefix]
		}
		#
		return $PrefixList_tmp
	}

	
	# Given list of ipv6 prefixes this command if possible summarizes contiguous IPv6 prefixes to an aggregate network.
	#
	# PrefixList - list of ipv6 prefixes with or without mask
	#
	# Return     - aggregated ipv6 prefix list 
	proc Collapse {PrefixList} {
		set PrefixList [CheckAndNormilize $PrefixList]
		#
		set CAN_NORMILIZE_MORE 1
		set NO_ITEM ""
		while {$CAN_NORMILIZE_MORE} {
			set Ret {}
			#
			set PrefixList [lsort -incr $PrefixList]
			#
			set CAN_NORMILIZE_MORE 0
			#
			for {set idx 0} {$idx < [llength $PrefixList]} {incr idx} {
				set nextidx [expr {$idx + 1}]

				set item     [lindex $PrefixList $idx]
				set nextitem [lindex $PrefixList $nextidx]

				if {$nextitem eq $NO_ITEM} {
					lappend Ret $item
					continue
				}
				#
				set itemmask     [mask $item]
				set nextitemmask [mask $nextitem]
				#
				if {$itemmask ne $nextitemmask} {
					lappend Ret $item
					continue
				}

				set adjacentitem [NextNet $item]

				if {[Prefix $nextitem] ne $adjacentitem} {
					lappend Ret $item
					continue
				}

				set upmask [expr {$itemmask - 1}]
				set upitem [join [list [Prefix $item] $upmask] /]

				# Maybe just checking the llength of the result is enough ?
				if {[ReduceToAggregates [list $item $nextitem $upitem]] != [list $upitem]} {
					lappend Ret $item
					continue
				}

				set CAN_NORMILIZE_MORE 1

				incr idx
				lappend Ret $upitem
			}

			set PrefixList $Ret
		}
		return $PrefixList
	}

	
	# Same as Collapse but returns ipv6 prefixes in compact format 
	proc collapse {PrefixList} {
		foreach Prefix [Collapse $PrefixList] {
			lappend PrefixList_tmp [compress $Prefix]
		}
		#
		return $PrefixList_tmp
	}

	
	# Given lists of ipv6 prefixes this command subtracts second list of prefixs from the first one and returns new list of ipv6 prefixes
	#
	# PosPrefixList - list of ipv6 prefixes from which subtraction should be done
	# NegPrefixList - list of ipv6 prefixes which should be subtracted
	#
	# Return        - list of calculated ipv6 prefixes
	proc Subtract {PosPrefixList NegPrefixList} {
		set PosPrefixList [CheckAndNormilize $PosPrefixList]
		set PosPrefixList [lsort -command SortLargeToSmallMask [ReduceToAggregates $PosPrefixList]]
		#
		if {$NegPrefixList eq ""} {return $PosPrefixList}
		#
		#Reduce to aggregate negative prefixes and sort from largest to smallest
		set NegPrefixList [CheckAndNormilize $NegPrefixList]
		set NegPrefixList [lsort -command SortLargeToSmallMask [ReduceToAggregates $NegPrefixList]]
		#Check if we have negative prefixes
			foreach NegPrefix $NegPrefixList {
			#Get negative prefix mask
			set NegPrefMask [mask $NegPrefix]
			#
			foreach PosPrefix $PosPrefixList {
				#Check if negative subnet is overlaping with positive
				if [isOverlap $PosPrefix $NegPrefix] {
					#Check if negative prefix is already in positive prefix list
					if {$NegPrefix in $PosPrefix} {
						set PosPrefixList [Lpop $PosPrefixList $NegPrefix]
					} else {
						set PosPrefixList [concat [Lpop $PosPrefixList $PosPrefix] [RecSubtract $PosPrefix [mask $PosPrefix] $NegPrefix $NegPrefMask]]
					}
					#
					break
				}
			}
		}
		#
		return $PosPrefixList
	}

	proc RecSubtract {PosPrefixList PosMask NegPrefix NegPrefMask} {
		set Mask [expr {$PosMask + 1}]
		#
		set PosPrefixExpanded [ExpandSubnet $PosPrefixList $Mask]
		#
		foreach PosPrefix $PosPrefixExpanded {
			#Check if negative subnet is overlaping with positive
			if [isOverlap $PosPrefix $NegPrefix] {
				set NextPosPrefix $PosPrefix
				set PosPrefixList [Lpop $PosPrefixExpanded $NextPosPrefix]
				break
			}
		}
		#
		if {$Mask != $NegPrefMask} {
			append PosPrefixList " [RecSubtract $NextPosPrefix $Mask $NegPrefix $NegPrefMask]"
		}
		#
		return "$PosPrefixList "
	}

	# Same as Subtract but returns ipv6 prefixes in compact format 
	proc subtract {PosPrefixList NegPrefixList} {
		set PrefixList_tmp {}
		#
		foreach Prefix [Subtract $PosPrefixList $NegPrefixList] {
			lappend PrefixList_tmp [compress $Prefix]
		}
		#
		return $PrefixList_tmp
	}


	# Calculate new subnets given IPv6 prefix, desired new prefix length and offset
	#
	# IPPrefix - ipv6 address with or without mask
	# NewMask  - prefix length of desired new subnetworks
	# Offset   - number of subnetwork which should be returnd (default 0: all subnets)
	#
	# return   - IPv6 prefix list of new subnetworks 
	proc ExpandSubnet {IPPrefix NewMask {Offset 0}} {
		set OldMask [mask $IPPrefix]
		set Prefix  [Prefix $IPPrefix]
		#
		set NumSubnets [expr {round(pow(2, ($NewMask - $OldMask)))}]
		#
		if {$Offset <= $NumSubnets} {
			set NumSubnets $Offset
		}
		#
		set ret {}
		for {set idx 0} {$idx < $NumSubnets} {incr idx} {
			lappend ret "${Prefix}/${NewMask}"
			set Prefix [Prefix [NextNet $Prefix/$NewMask]]
		}
		return $ret
	}

	# Same as ExpandSubnet but returns ipv6 prefixes in compact format 
	proc expandSubnet {IPPrefix NewMask {Offset 0}} {
		set PrefixList_tmp {}
		#
		foreach Prefix [ExpandSubnet $IPPrefix $NewMask $Offset] {
			lappend PrefixList_tmp [compress $Prefix]
		}
		#
		return $PrefixList_tmp
	}

	
	# Given list of ipv6 addreses calculates mapping to ethernet multicast mac address
	#
	# IpAddrList - list of ipv6 addresses
	#
	# return     - list of ethernet addresses mapped to ipv6 multicast address last 32 bits
	proc ipv6ToEthMulticast {IpAddrList} {
		variable IPV6_MULTICAST_PREFIX
		variable EHT_IPV6_MUL_FIRST_4_HEX_CHAR
		#
		set EthMulAddrList {}
		#
		try {
			foreach IPv6Addr $IpAddrList {
				if {[prefix $IPv6Addr/8] eq $IPV6_MULTICAST_PREFIX} {
					lassign [IPtoHexAndGetMask $IPv6Addr] IpAddr_tmp Mask
					set IPv6AddrLast8HexChar [string range $IpAddr_tmp end-7 end]
					lappend EthMulAddrList [string tolower [join [concat $EHT_IPV6_MUL_FIRST_4_HEX_CHAR $IPv6AddrLast8HexChar] {}]]
				}
			}
			#
			return $EthMulAddrList
		} on error {result options} {
			return -code error $result
		}
	}
	
}
