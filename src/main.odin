package main

import "core:fmt"
import "core:net"
import "core:os"

main :: proc() {
	socket, err := net.create_socket(.IP4, .TCP)
	if err != nil {
		fmt.eprintf("failed to create socket %s\n", err)
		os.exit(1)
	}
}
