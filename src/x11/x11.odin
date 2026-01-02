#+build !wasm32
package x11

import "../game"
import "core:bytes"
import "core:image/png"
import "core:math/bits"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:strings"
import "core:sys/linux"


AuthToken :: [16]u8

AuthEntry :: struct {
	family:    u16,
	auth_name: []u8,
	auth_data: []u8,
}

Screen :: struct #packed {
	id:             u32,
	colormap:       u32,
	white:          u32,
	black:          u32,
	input_mask:     u32,
	width:          u16,
	height:         u16,
	width_mm:       u16,
	height_mm:      u16,
	maps_min:       u16,
	maps_max:       u16,
	root_visual_id: u32,
	backing_store:  u8,
	save_unders:    u8,
	root_depth:     u8,
	depths_count:   u8,
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
	return cast(u32)((cast(i32)x + 3) & mask)
}

read_x11_auth_entry :: proc(buffer: ^bytes.Buffer) -> (AuthEntry, bool) {
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

	address := make([]u8, address_len)
	{
		n_read, err := bytes.buffer_read(buffer, address)
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

	display_number := make([]u8, display_number_len)
	{
		n_read, err := bytes.buffer_read(buffer, display_number)
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

	entry.auth_name = make([]u8, auth_name_len)
	{
		n_read, err := bytes.buffer_read(buffer, entry.auth_name)
		assert(err == .None)
		assert(n_read == cast(int)auth_name_len)
	}

	auth_data_len: u16 = 0
	{
		n_read, err := bytes.buffer_read(buffer, mem.ptr_to_bytes(&auth_data_len))
		assert(err == .None)

		auth_data_len = bits.byte_swap(auth_data_len)
		assert(n_read == size_of(auth_data_len))
	}

	entry.auth_data = make([]u8, auth_data_len)
	{
		n_read, err := bytes.buffer_read(buffer, entry.auth_data)
		assert(err == .None)
		assert(n_read == cast(int)auth_data_len)
	}


	return entry, true
}

load_x11_auth_token :: proc(allocator := context.allocator) -> (token: AuthToken, ok: bool) {
	context.allocator = allocator
	defer free_all(allocator)

	filename_env := os.get_env("XAUTHORITY")

	filename :=
		len(filename_env) != 0 ? filename_env : filepath.join([]string{os.get_env("HOME"), ".Xauthority"})

	data := os.read_entire_file_from_filename(filename) or_return

	buffer := bytes.Buffer{}
	bytes.buffer_init(&buffer, data[:])


	for {
		auth_entry := read_x11_auth_entry(&buffer) or_break

		if auth_entry.family == AUTH_ENTRY_FAMILY_LOCAL &&
		   slice.equal(auth_entry.auth_name, transmute([]u8)AUTH_ENTRY_MAGIC_COOKIE) &&
		   len(auth_entry.auth_data) == size_of(AuthToken) {

			mem.copy_non_overlapping(
				raw_data(&token),
				raw_data(auth_entry.auth_data),
				size_of(AuthToken),
			)
			return token, true
		}
	}

	// Did not find a fitting token.
	return {}, false
}

connect_x11_socket :: proc() -> os.Socket {
	defer free_all(context.temp_allocator)

	SockaddrUn :: struct #packed {
		sa_family: os.ADDRESS_FAMILY,
		sa_data:   [108]u8,
	}

	socket, err := os.socket(os.AF_UNIX, os.SOCK_STREAM, 0)
	assert(err == os.ERROR_NONE)

	display_env := strings.trim_left(os.get_env("DISPLAY"), ":")
	display_socket := strings.concatenate(
		[]string{"/tmp/.X11-unix/X", display_env},
		allocator = context.temp_allocator,
	)

	possible_socket_paths := [3]string{display_socket, "/tmp/.X11-unix/X0", "/tmp/.X11-unix/X1"}

	for &socket_path in possible_socket_paths {
		addr := SockaddrUn {
			sa_family = cast(u16)os.AF_UNIX,
		}
		mem.copy_non_overlapping(&addr.sa_data, raw_data(socket_path), len(socket_path))

		err = os.connect(socket, cast(^os.SOCKADDR)&addr, size_of(addr))
		if (err == os.ERROR_NONE) {return socket}
	}

	assert(false)
	return {}
}


x11_handshake :: proc(socket: os.Socket, auth_token: ^AuthToken) -> ConnectionInformation {

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
		padding := [2]u8{0, 0}
		n_sent, err := linux.writev(
			cast(linux.Fd)socket,
			[]linux.IO_Vec {
				{base = &request, len = size_of(Request)},
				{base = raw_data(AUTH_ENTRY_MAGIC_COOKIE), len = len(AUTH_ENTRY_MAGIC_COOKIE)},
				{base = raw_data(padding[:]), len = len(padding)},
				{base = raw_data(auth_token[:]), len = len(auth_token)},
			},
		)
		assert(err == .NONE)
		assert(
			n_sent ==
			size_of(Request) + len(AUTH_ENTRY_MAGIC_COOKIE) + len(padding) + len(auth_token),
		)
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
	}

	return (ConnectionInformation {
				resource_id_base = dynamic_response.resource_id_base,
				resource_id_mask = dynamic_response.resource_id_mask,
				root_screen = screen,
			})
}

next_x11_id :: proc(current_id: u32, info: ConnectionInformation) -> u32 {
	return 1 + ((info.resource_id_mask & (current_id)) | info.resource_id_base)
}

x11_create_graphical_context :: proc(socket: os.Socket, gc_id: u32, root_id: u32) {
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

x11_create_window :: proc(
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
	EVENT_FLAG_KEY_PRESS: u32 = 0x1
	EVENT_FLAG_KEY_RELEASE: u32 = 0x2
	EVENT_FLAG_BUTTON_PRESS: u32 = 0x4
	EVENT_FLAG_BUTTON_RELEASE: u32 = 0x8
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
		class          = CLASS_INPUT_OUTPUT,
		root_visual_id = root_visual_id,
		bitmask        = flags,
		value1         = BACKGROUND_PIXEL_COLOR,
		value2         = EVENT_FLAG_EXPOSURE | EVENT_FLAG_BUTTON_RELEASE | EVENT_FLAG_BUTTON_PRESS | EVENT_FLAG_KEY_PRESS | EVENT_FLAG_KEY_RELEASE,
	}

	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}
}

x11_map_window :: proc(socket: os.Socket, window_id: u32) {
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
		window_id      = window_id,
	}
	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}

}

x11_put_image :: proc(
	socket: os.Socket,
	drawable_id: u32,
	gc_id: u32,
	width: u16,
	height: u16,
	dst_x: u16,
	dst_y: u16,
	depth: u8,
	data: []u8,
) {
	opcode: u8 : 72

	Request :: struct #packed {
		opcode:         u8,
		format:         u8,
		request_length: u16,
		drawable_id:    u32,
		gc_id:          u32,
		width:          u16,
		height:         u16,
		dst_x:          u16,
		dst_y:          u16,
		left_pad:       u8,
		depth:          u8,
		pad1:           u16,
	}

	data_length_padded := round_up_4(cast(u32)len(data))

	request := Request {
		opcode         = opcode,
		format         = 2, // ZPixmap
		request_length = cast(u16)(6 + data_length_padded / 4),
		drawable_id    = drawable_id,
		gc_id          = gc_id,
		width          = width,
		height         = height,
		dst_x          = dst_x,
		dst_y          = dst_y,
		depth          = depth,
	}
	{
		padding_len := data_length_padded - cast(u32)len(data)

		n_sent, err := linux.writev(
			cast(linux.Fd)socket,
			[]linux.IO_Vec {
				{base = &request, len = size_of(Request)},
				{base = raw_data(data), len = len(data)},
				{base = raw_data(data), len = cast(uint)padding_len},
			},
		)
		assert(err == .NONE)
		assert(n_sent == size_of(Request) + len(data) + cast(int)padding_len)
	}
}

render :: proc(socket: os.Socket, scene: ^game.Scene) {
	for entity, i in scene.displayed_entities {
		rect := game.ASSET_COORDINATES[entity]
		row, column := game.idx_to_row_column(i)

		x11_copy_area(
			socket,
			scene.sprite_pixmap_id,
			scene.window_id,
			scene.gc_id,
			rect.x,
			rect.y,
			cast(u16)column * game.ENTITIES_WIDTH,
			cast(u16)row * game.ENTITIES_HEIGHT,
			game.ENTITIES_WIDTH,
			game.ENTITIES_HEIGHT,
		)
	}
}

wait_for_x11_events :: proc(socket: os.Socket, scene: ^game.Scene) {
	GenericEvent :: struct #packed {
		code: u8,
		pad:  [31]u8,
	}
	assert(size_of(GenericEvent) == 32)

	KeyReleaseEvent :: struct #packed {
		code:            u8,
		detail:          u8,
		sequence_number: u16,
		time:            u32,
		root_id:         u32,
		event:           u32,
		child_id:        u32,
		root_x:          u16,
		root_y:          u16,
		event_x:         u16,
		event_y:         u16,
		state:           u16,
		same_screen:     bool,
		pad1:            u8,
	}
	assert(size_of(KeyReleaseEvent) == 32)

	ButtonReleaseEvent :: struct #packed {
		code:        u8,
		detail:      u8,
		seq_number:  u16,
		timestamp:   u32,
		root:        u32,
		event:       u32,
		child:       u32,
		root_x:      u16,
		root_y:      u16,
		event_x:     u16,
		event_y:     u16,
		state:       u16,
		same_screen: bool,
		pad1:        u8,
	}
	assert(size_of(ButtonReleaseEvent) == 32)

	EVENT_EXPOSURE: u8 : 0xc
	EVENT_KEY_RELEASE: u8 : 0x3
	EVENT_BUTTON_RELEASE: u8 : 0x5

	KEYCODE_ENTER: u8 : 36

	for {
		generic_event := GenericEvent{}
		n_recv, err := os.recv(socket, mem.ptr_to_bytes(&generic_event), 0)
		if err == os.EPIPE || n_recv == 0 {
			os.exit(0) // The end.
		}

		assert(err == os.ERROR_NONE)
		assert(n_recv == size_of(GenericEvent))

		switch generic_event.code {
		case EVENT_EXPOSURE:
			render(socket, scene)

		case EVENT_KEY_RELEASE:
			event := transmute(KeyReleaseEvent)generic_event
			if event.detail == KEYCODE_ENTER {
				game.reset(scene)
				render(socket, scene)
			}

		case EVENT_BUTTON_RELEASE:
			event := transmute(ButtonReleaseEvent)generic_event
			game.on_cell_clicked(event.event_x, event.event_y, scene)
			render(socket, scene)
		}
	}
}

x11_copy_area :: proc(
	socket: os.Socket,
	src_id: u32,
	dst_id: u32,
	gc_id: u32,
	src_x: u16,
	src_y: u16,
	dst_x: u16,
	dst_y: u16,
	width: u16,
	height: u16,
) {
	opcode: u8 : 62
	Request :: struct #packed {
		opcode:         u8,
		pad1:           u8,
		request_length: u16,
		src_id:         u32,
		dst_id:         u32,
		gc_id:          u32,
		src_x:          u16,
		src_y:          u16,
		dst_x:          u16,
		dst_y:          u16,
		width:          u16,
		height:         u16,
	}

	request := Request {
		opcode         = opcode,
		request_length = 7,
		src_id         = src_id,
		dst_id         = dst_id,
		gc_id          = gc_id,
		src_x          = src_x,
		src_y          = src_y,
		dst_x          = dst_x,
		dst_y          = dst_y,
		width          = width,
		height         = height,
	}
	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}
}

x11_create_pixmap :: proc(
	socket: os.Socket,
	window_id: u32,
	pixmap_id: u32,
	width: u16,
	height: u16,
	depth: u8,
) {
	opcode: u8 : 53

	Request :: struct #packed {
		opcode:         u8,
		depth:          u8,
		request_length: u16,
		pixmap_id:      u32,
		drawable_id:    u32,
		width:          u16,
		height:         u16,
	}

	request := Request {
		opcode         = opcode,
		depth          = depth,
		request_length = 4,
		pixmap_id      = pixmap_id,
		drawable_id    = window_id,
		width          = width,
		height         = height,
	}

	{
		n_sent, err := os.send(socket, mem.ptr_to_bytes(&request), 0)
		assert(err == os.ERROR_NONE)
		assert(n_sent == size_of(Request))
	}
}

run :: proc() {
	png_data := #load("../sprite.png")
	sprite, err := png.load_from_bytes(png_data, {})
	assert(err == nil)
	sprite_data := make([]u8, sprite.height * sprite.width * 4)

	// Convert the image format from the sprite (RGB) into the X11 image format (BGRX).
	for i := 0; i < sprite.height * sprite.width - 3; i += 1 {
		sprite_data[i * 4 + 0] = sprite.pixels.buf[i * 3 + 2] // R -> B
		sprite_data[i * 4 + 1] = sprite.pixels.buf[i * 3 + 1] // G -> G
		sprite_data[i * 4 + 2] = sprite.pixels.buf[i * 3 + 0] // B -> R
		sprite_data[i * 4 + 3] = 0 // pad
	}

	auth_token, _ := load_x11_auth_token(context.temp_allocator)

	socket := connect_x11_socket()
	connection_information := x11_handshake(socket, &auth_token)

	gc_id := next_x11_id(0, connection_information)
	x11_create_graphical_context(socket, gc_id, connection_information.root_screen.id)

	window_id := next_x11_id(gc_id, connection_information)
	x11_create_window(
		socket,
		window_id,
		connection_information.root_screen.id,
		200,
		200,
		game.ENTITIES_COLUMN_COUNT * game.ENTITIES_WIDTH,
		game.ENTITIES_ROW_COUNT * game.ENTITIES_HEIGHT,
		connection_information.root_screen.root_visual_id,
	)

	img_depth: u8 = 24
	pixmap_id := next_x11_id(window_id, connection_information)
	x11_create_pixmap(
		socket,
		window_id,
		pixmap_id,
		cast(u16)sprite.width,
		cast(u16)sprite.height,
		img_depth,
	)
	scene := game.Scene {
		window_id        = window_id,
		gc_id            = gc_id,
		sprite_pixmap_id = pixmap_id,
	}
	game.reset(&scene)

	x11_put_image(
		socket,
		scene.sprite_pixmap_id,
		scene.gc_id,
		cast(u16)sprite.width,
		cast(u16)sprite.height,
		0,
		0,
		img_depth,
		sprite_data,
	)

	x11_map_window(socket, window_id)

	wait_for_x11_events(socket, &scene)
}
