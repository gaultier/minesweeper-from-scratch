package main

import "core:bytes"
import "core:c"
import "core:fmt"
import "core:math/bits"
import "core:mem"
import "core:net"
import "core:os"
import "core:slice"
import "core:testing"

AuthToken :: [16]u8

AuthEntry :: struct {
	family:    u16,
	auth_name: []u8,
	auth_data: []u8,
}


Screen :: struct #packed {
	id:             u32,
	colormap:       u32,
	black:          u32,
	white:          u32,
	input_mask:     u32,
	height:         u16,
	width:          u16,
	height_mm:      u16,
	width_mm:       u16,
	maps_max:       u16,
	maps_min:       u16,
	root_visual_id: u32,
	backing_store:  u8,
	save_unders:    u8,
	depth:          u8,
	depths:         u8,
}

ConnectionInformation :: struct {
	root_screen:      Screen,
	resource_id_base: u32,
	resource_id_mask: u32,
}


AUTH_ENTRY_FAMILY_LOCAL: u16 : 1
AUTH_ENTRY_MAGIC_COOKIE: string : "MIT-MAGIC-COOKIE-1"

round_up_4 :: #force_inline proc(x: u32) -> u32 {
	mask: i32 = -4
	return transmute(u32)((transmute(i32)x + 3) & mask)
}

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
				raw_data(&token),
				raw_data(auth_entry.auth_data),
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


handshake :: proc(socket: os.Socket, auth_token: ^AuthToken) -> ConnectionInformation {

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


	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}

	{
		n_sent, err := os.send(socket, transmute([]u8)AUTH_ENTRY_MAGIC_COOKIE, 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == len(AUTH_ENTRY_MAGIC_COOKIE))
	}
	{
		padding := [2]u8{0, 0}
		n_sent, err := os.send(socket, padding[:], 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == 2)
	}
	{
		n_sent, err := os.send(socket, auth_token[:], 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == len(auth_token))
	}


	StaticResponse :: struct #packed {
		success:       u8,
		pad1:          u8,
		major_version: u16,
		minor_version: u16,
		length:        u16,
	}

	static_response := StaticResponse{}
	{
		n_recv, err := os.recv(socket, mem.ptr_to_bytes(&static_response), 0)
		assert(err == os.ERROR_NONE)
		assert(n_recv == size_of(StaticResponse))
		assert(static_response.success == 1)

		fmt.println(static_response)
	}


	recv_buf: [1 << 15]u8 = {}
	{
		assert(len(recv_buf) >= cast(u32)static_response.length * 4)

		n_recv, err := os.recv(socket, recv_buf[:], 0)
		assert(err == os.ERROR_NONE)
		assert(n_recv == cast(u32)static_response.length * 4)
	}


	DynamicResponse :: struct #packed {
		release_number:              u32,
		resource_id_base:            u32,
		resource_id_mask:            u32,
		motion_buffer_size:          u32,
		vendor_length:               u16,
		maximum_request_length:      u16,
		screens_in_root_count:       u8,
		formats_count:               u8,
		image_byte_order:            u8,
		bitmap_format_bit_order:     u8,
		bitmap_format_scanline_unit: u8,
		bitmap_format_scanline_pad:  u8,
		min_keycode:                 u8,
		max_keycode:                 u8,
		pad2:                        u32,
	}

	read_buffer := bytes.Buffer{}
	bytes.buffer_init(&read_buffer, recv_buf[:])

	dynamic_response := DynamicResponse{}
	{
		n_read, err := bytes.buffer_read(&read_buffer, mem.ptr_to_bytes(&dynamic_response))
		assert(err == .None)
		assert(n_read == size_of(DynamicResponse))

		fmt.println(dynamic_response)
	}


	// Skip over the vendor information.
	bytes.buffer_next(&read_buffer, cast(int)round_up_4(cast(u32)dynamic_response.vendor_length))
	// Skip over the format information (each 8 bytes long).
	bytes.buffer_next(&read_buffer, 8 * cast(int)dynamic_response.formats_count)

	screen := Screen{}
	{
		n_read, err := bytes.buffer_read(&read_buffer, mem.ptr_to_bytes(&screen))
		assert(err == .None)
		assert(n_read == size_of(screen))

		fmt.println(screen)
	}

	return(
		ConnectionInformation {
			resource_id_base = dynamic_response.resource_id_base,
			resource_id_mask = dynamic_response.resource_id_mask,
			root_screen = screen,
		} \
	)
}

next_id :: proc(current_id: u32, info: ConnectionInformation) -> u32 {
	return 1 + (info.resource_id_mask & (current_id) | info.resource_id_base)
}

create_graphical_context :: proc(socket: os.Socket, gc_id: u32, root_id: u32) {
	opcode: u8 : 55
	FLAG_GC_BG: u32 : 8
	BITMASK: u32 : FLAG_GC_BG
	VALUE1: u32 : 0x00_00_ff_00

	Request :: struct #packed {
		opcode:   u8,
		pad1:     u8,
		length:   u16,
		id:       u32,
		drawable: u32,
		bitmask:  u32,
		value1:   u32,
	}
	request := Request {
		opcode   = opcode,
		length   = 5,
		id       = gc_id,
		drawable = root_id,
		bitmask  = BITMASK,
		value1   = VALUE1,
	}

	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}
}

create_window :: proc(
	socket: os.Socket,
	window_id: u32,
	parent_id: u32,
	x: u16,
	y: u16,
	width: u16,
	height: u16,
	root_visual_id: u32,
) {
	FLAG_WIN_BG_PIXEL: u32 : 2
	FLAG_WIN_EVENT: u32 : 0x800
	FLAG_COUNT: u16 : 2
	EVENT_FLAG_EXPOSURE: u32 = 0x80_00
	flags: u32 : FLAG_WIN_BG_PIXEL | FLAG_WIN_EVENT
	depth: u8 : 24
	border_width: u16 : 0
	CLASS_INPUT_OUTPUT: u16 : 1
	opcode: u8 : 1
	BACKGROUND_PIXEL_COLOR: u32 : 0x00_ff_ff_00

	Request :: struct #packed {
		opcode:         u8,
		depth:          u8,
		request_length: u16,
		window_id:      u32,
		parent_id:      u32,
		x:              u16,
		y:              u16,
		width:          u16,
		height:         u16,
		border_width:   u16,
		class:          u16,
		root_visual_id: u32,
		bitmask:        u32,
		value1:         u32,
		value2:         u32,
	}
	request := Request {
		opcode         = opcode,
		depth          = depth,
		request_length = 8 + FLAG_COUNT,
		window_id      = window_id,
		parent_id      = parent_id,
		x              = x,
		y              = y,
		width          = width,
		height         = height,
		border_width   = border_width,
		class          = class,
		root_visual_id = root_visual_id,
		bitmask        = flags,
		value1         = BACKGROUND_PIXEL_COLOR,
		value2         = EVENT_FLAG_EXPOSURE,
	}

	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}
}

map_window :: proc(socket: os.Socket, window_id: u32) {
	opcode: u8 : 8

	Request :: struct #packed {
		opcode:         u8,
		pad1:           u8,
		request_length: u16,
		window_id:      u32,
	}
	request := Request {
		opcode         = opcode,
		request_length = 2,
		window_id      = 1,
	}
	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}

	response := [8]u8{}
	os.recv(socket, response[:], 0)
}

main :: proc() {
	auth_token := load_auth_token()

	socket := connect()
	connection_information := handshake(socket, &auth_token)
	fmt.println(connection_information)

	window_id := next_id(0, connection_information)
	create_window(
		socket,
		window_id,
		connection_information.root_screen.id,
		200,
		200,
		800,
		600,
		connection_information.root_screen.root_visual_id,
	)

	gc_id := next_id(window_id, connection_information)
	create_graphical_context(socket, gc_id, connection_information.root_screen.id)

	map_window(socket, window_id)
}


@(test)
test_round_up_4 :: proc(_: ^testing.T) {
	assert(round_up_4(0) == 0)
	assert(round_up_4(1) == 4)
	assert(round_up_4(2) == 4)
	assert(round_up_4(3) == 4)
	assert(round_up_4(4) == 4)
	assert(round_up_4(5) == 8)
	assert(round_up_4(6) == 8)
	assert(round_up_4(7) == 8)
	assert(round_up_4(8) == 8)
}
