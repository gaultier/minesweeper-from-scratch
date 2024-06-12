package main

import "core:c"
import "core:fmt"
import "core:mem"
import "core:os"

connect :: proc() -> os.Socket {
	SockaddrUn :: struct #packed {
		sa_family: os.ADDRESS_FAMILY,
		sa_data:   [108]c.char,
	}

	socket, err := os.socket(os.AF_UNIX, os.SOCK_STREAM, 0)
	if err != os.ERROR_NONE {
		fmt.eprintf("failed to create socket %s\n", err)
		os.exit(1)
	}

	socket_path := [?]c.char {
		'/',
		't',
		'm',
		'p',
		'/',
		'.',
		'X',
		'1',
		'1',
		'-',
		'u',
		'n',
		'i',
		'x',
		'/',
		'X',
		'0',
	}
	addr := SockaddrUn {
		sa_family = cast(u16)os.AF_UNIX,
		sa_data   = {},
	}
	mem.copy_non_overlapping(&addr.sa_data, raw_data(&socket_path), len(socket_path))

	if err := os.connect(socket, cast(^os.SOCKADDR)&addr, size_of(addr)); err != os.ERROR_NONE {
		fmt.eprintf("failed to connect %s\n", err)
		os.exit(1)
	}

	return socket
}


handshake :: proc(socket: os.Socket) {
	authorization: string : "MIT-MAGIC-COOKIE-1"

	Request :: struct #packed {
		endianness:                   u8,
		pad1:                         u8,
		major_version:                u16,
		minor_version:                u16,
		authorization_len:            u16,
		authorization_data_len, pad2: u16,
	}
	request := Request {
		endianness        = 'l',
		major_version     = 11,
		authorization_len = len(authorization),
	}
}

main :: proc() {
	socket := connect()
}
