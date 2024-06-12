package main

import "core:c"
import "core:fmt"
import "core:mem"
import "core:net"
import "core:os"

connect :: proc() -> os.Socket {
	SockaddrUn :: struct #packed {
		sa_family: os.ADDRESS_FAMILY,
		sa_data:   [108]c.char,
	}

	socket, err := os.socket(os.AF_UNIX, os.SOCK_STREAM, 0)
	assert(err == os.ERROR_NONE)

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
	}
	mem.copy_non_overlapping(&addr.sa_data, raw_data(&socket_path), len(socket_path))

	err = os.connect(socket, cast(^os.SOCKADDR)&addr, size_of(addr))
	assert(err == os.ERROR_NONE)

	return socket
}


handshake :: proc(socket: os.Socket) {
	authorization: string : "MIT-MAGIC-COOKIE-1"

	Request :: struct #packed {
		endianness:             u8,
		pad1:                   u8,
		major_version:          u16,
		minor_version:          u16,
		authorization_len:      u16,
		authorization_data_len: u16,
		pad2:                   u16,
	}

	request := Request {
		endianness             = 'l',
		major_version          = 11,
		// TODO: Magic cookie auth?
		authorization_len      = 0, // len(authorization),
		authorization_data_len = 0, // 16,
	}


	n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
	assert(err == os.ERROR_NONE)
	assert(n_sent == size_of(Request))


	Response :: struct #packed {
		success:       u8,
		pad1:          u8,
		major_version: u16,
		minor_version: u16,
		length:        u16,
		// release_number:              u32,
		// resource_id_base:            u32,
		// resource_id_mask:            u32,
		// motion_buffer_size:          u32,
		// vendor_length:               u16,
		// maximum_request_length:      u16,
		// screens_in_root_count:       u8,
		// formats_count:               u8,
		// image_byte_order:            u8,
		// bitmap_format_bit_order:     u8,
		// bitmap_format_scanline_unit: u8,
		// bitmap_format_scanline_pad:  u8,
		// min_keycode:                 u8,
		// max_keycode:                 u8,
		// pad2:                        u32,
	}

	response := Response{}
	n_recv: u32 = 0
	n_recv, err = os.recv(socket, mem.ptr_to_bytes(&response), 0)
	assert(err == os.ERROR_NONE)
	assert(n_recv == size_of(Response))
	assert(response.success == 1)

	fmt.println(response)


	recv_buf: [1 << 15]u8 = {}
	n_recv, err = os.recv(socket, recv_buf[:], 0)
	assert(err == os.ERROR_NONE)
	assert(n_recv == cast(u32)response.length * 4)
}

main :: proc() {
	socket := connect()
	handshake(socket)
}
