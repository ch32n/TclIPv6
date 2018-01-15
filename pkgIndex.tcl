if {![package vsatisfies [package provide Tcl] 8.5]} return
package ifneeded ipv6 1.0 [string map [list @ $dir] {source [file join {@} ipv6.tcl]}]
