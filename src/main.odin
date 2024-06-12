package main

import "core:bytes"
import "core:c"
import "core:fmt"
import "core:math/bits"
import "core:mem"
import "core:net"
import "core:os"
import "core:slice"

AuthToken :: [16]u8

AuthEntry :: struct {
	family:    u16,
	auth_name: []u8,
	auth_data: []u8,
}

AUTH_ENTRY_FAMILY_LOCAL: u16 : 1
AUTH_ENTRY_MAGIC_COOKIE: string : "MIT-MAGIC-COOKIE-1"

read_auth_entry :: proc(buffer: ^bytes.Buffer) -> (AuthEntry, bool) {
	entry := AuthEntry{}

	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&entry.family))
		if err == .EOF {return {}, false}

		assert(err == .None)
		assert(n_read == size_of(entry.family))
	}

	address_len: u16 = 0
	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&address_len))
		assert(err == .None)

		address_len = bits.byte_swap(address_len)
		assert(n_read == size_of(address_len))
	}

	address := [256]u8{}
	{
		assert(address_len <= len(address))

		n_read, err := bytes.buffer_read(buffer, address[:address_len])
		assert(err == .None)
		assert(n_read == cast(int)address_len)
	}

	display_number_len: u16 = 0
	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&display_number_len))
		assert(err == .None)

		display_number_len = bits.byte_swap(display_number_len)
		assert(n_read == size_of(display_number_len))
	}

	display_number := [256]u8{}
	{
		assert(display_number_len <= len(display_number))

		n_read, err := bytes.buffer_read(buffer, display_number[:display_number_len])
		assert(err == .None)
		assert(n_read == cast(int)display_number_len)
	}

	auth_name_len: u16 = 0
	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&auth_name_len))
		assert(err == .None)

		auth_name_len = bits.byte_swap(auth_name_len)
		assert(n_read == size_of(auth_name_len))
	}

	auth_name := [256]u8{}
	{
		assert(auth_name_len <= len(auth_name))

		n_read, err := bytes.buffer_read(buffer, auth_name[:auth_name_len])
		assert(err == .None)
		assert(n_read == cast(int)auth_name_len)

		entry.auth_name = slice.clone(auth_name[:auth_name_len])
	}

	auth_data_len: u16 = 0
	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&auth_data_len))
		assert(err == .None)

		auth_data_len = bits.byte_swap(auth_data_len)
		assert(n_read == size_of(auth_data_len))
	}

	auth_data := [256]u8{}
	{
		assert(auth_data_len <= len(auth_data))

		n_read, err := bytes.buffer_read(buffer, auth_data[:auth_data_len])
		assert(err == .None)
		assert(n_read == cast(int)auth_data_len)

		entry.auth_data = slice.clone(auth_data[:auth_data_len])
	}


	return entry, true
}

load_auth_token :: proc() -> AuthToken {
	filename_env := os.get_env("XAUTHORITY")
	data, ok := os.read_entire_file_from_filename(filename_env)
	assert(ok)

	buffer := bytes.Buffer{}
	bytes.buffer_init(&buffer, data[:])


	for {
		auth_entry, ok := read_auth_entry(&buffer)
		if !ok {
			break
		}

		if auth_entry.family == AUTH_ENTRY_FAMILY_LOCAL &&
		   slice.equal(auth_entry.auth_name, transmute([]u8)AUTH_ENTRY_MAGIC_COOKIE) &&
		   len(auth_entry.auth_data) == size_of(AuthToken) {

			token := AuthToken{}
			mem.copy_non_overlapping(
				raw_data(auth_entry.auth_data),
				raw_data(&token),
				size_of(AuthToken),
			)
			return token
		}
	}

	os.exit(1)
}

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


handshake :: proc(socket: os.Socket, auth_token: AuthToken) {

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
		authorization_len      = len(AUTH_ENTRY_MAGIC_COOKIE),
		authorization_data_len = size_of(AuthToken),
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
	auth_token := load_auth_token()

	socket := connect()
	handshake(socket, auth_token)
}
