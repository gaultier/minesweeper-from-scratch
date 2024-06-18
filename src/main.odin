package main

import "core:bytes"
import "core:c"
import "core:image/png"
import "core:math/bits"
import "core:math/rand"
import "core:mem"
import "core:os"
import "core:path/filepath"
import "core:slice"
import "core:sys/linux"
import "core:testing"

TILE_WIDTH :: 16
TILE_HEIGHT :: 16

Rect :: struct {
	x: u16,
	y: u16,
	w: u16,
	h: u16,
}

Entity_kind :: enum {
	Covered,
	// Digit_0,
	// Digit_1,
	// Digit_2,
	// Digit_3,
	// Digit_4,
	// Digit_5,
	// Digit_6,
	// Digit_7,
	// Digit_8,
	// Digit_9,
	// Dash,
	Uncovered_0,
	Uncovered_1,
	Uncovered_2,
	Uncovered_3,
	Uncovered_4,
	Uncovered_5,
	Uncovered_6,
	Uncovered_7,
	Uncovered_8,
	// Flag,
	Mine_exploded,
	// Mine_barred,
	Mine_idle,
	// Covered_question_mark,
	// Uncovered_question_mark,
}

ASSET_COORDINATES: [Entity_kind]Rect = {
	.Uncovered_0 = {x = 0 * 16, y = 22, w = 16, h = 16},
	.Uncovered_1 = {x = 1 * 16, y = 22, w = 16, h = 16},
	.Uncovered_2 = {x = 2 * 16, y = 22, w = 16, h = 16},
	.Uncovered_3 = {x = 3 * 16, y = 22, w = 16, h = 16},
	.Uncovered_4 = {x = 4 * 16, y = 22, w = 16, h = 16},
	.Uncovered_5 = {x = 5 * 16, y = 22, w = 16, h = 16},
	.Uncovered_6 = {x = 6 * 16, y = 22, w = 16, h = 16},
	.Uncovered_7 = {x = 7 * 16, y = 22, w = 16, h = 16},
	.Uncovered_8 = {x = 8 * 16, y = 22, w = 16, h = 16},
	.Covered = {x = 0, y = 38, w = 16, h = 16},
	.Mine_exploded = {x = 32, y = 40, w = 16, h = 16},
	.Mine_idle = {x = 64, y = 40, w = 16, h = 16},
}

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
	return transmute(u32)((transmute(i32)x + 3) & mask)
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

// TODO: Use a local arena as allocator.
load_x11_auth_token :: proc() -> (token: AuthToken, ok: bool) {
	filename_env := os.get_env("XAUTHORITY")

	filename :=
		len(filename_env) != 0 \
		? filename_env \
		: filepath.join([]string{os.get_env("HOME"), ".Xauthority"})

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

	return {}, false
}

connect_x11_socket :: proc() -> os.Socket {
	SockaddrUn :: struct #packed {
		sa_family: os.ADDRESS_FAMILY,
		sa_data:   [108]c.char,
	}

	socket, err := os.socket(os.AF_UNIX, os.SOCK_STREAM, 0)
	assert(err == os.ERROR_NONE)

	possible_socket_paths := [2]string{"/tmp/.X11-unix/X0", "/tmp/.X11-unix/X1"}
	for &socket_path in possible_socket_paths {
		addr := SockaddrUn {
			sa_family = cast(u16)os.AF_UNIX,
		}
		mem.copy_non_overlapping(&addr.sa_data, raw_data(socket_path), len(socket_path))

		err = os.connect(socket, cast(^os.SOCKADDR)&addr, size_of(addr))
		if (err == os.ERROR_NONE) {return socket}
	}

	os.exit(1)
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

render :: proc(socket: os.Socket, scene: ^Scene) {
	uncovered_count := 0
	for entity in scene.displayed_entities {
		uncovered_count += (entity == .Covered)
	}
	mine_count := 0
	for mine in scene.mines {
		mine_count += cast(int)mine
	}

	for entity, i in scene.displayed_entities {
		rect := ASSET_COORDINATES[entity]
		column: u16 = cast(u16)i % ENTITIES_COLUMN_COUNT
		row: u16 = cast(u16)i / ENTITIES_COLUMN_COUNT

		x11_copy_area(
			socket,
			scene.sprite_pixmap_id,
			scene.window_id,
			scene.gc_id,
			rect.x,
			rect.y,
			column * ENTITIES_WIDTH,
			row * ENTITIES_HEIGHT,
			rect.w,
			rect.h,
		)
	}
}

ENTITIES_ROW_COUNT :: 16
ENTITIES_COLUMN_COUNT :: 16
ENTITIES_WIDTH :: 16
ENTITIES_HEIGHT :: 16

Scene :: struct {
	window_id:                       u32,
	gc_id:                           u32,
	connection_information:          ConnectionInformation,
	sprite_data:                     []u8,
	sprite_pixmap_id:                u32,
	sprite_width:                    u16,
	sprite_height:                   u16,
	displayed_entities:              [ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]Entity_kind,
	// TODO: Bitfield?
	mines:                           [ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]bool,
	remaining_uncovered_cells_count: int,
}

wait_for_x11_events :: proc(socket: os.Socket, scene: ^Scene) {
	GenericEvent :: struct #packed {
		code: u8,
		pad:  [31]u8,
	}
	assert(size_of(GenericEvent) == 32)


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
	EVENT_KEY_PRESS: u8 : 0x2
	EVENT_KEY_RELEASE: u8 : 0x3
	EVENT_BUTTON_PRESS: u8 : 0x4
	EVENT_BUTTON_RELEASE: u8 : 0x5

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

		case EVENT_BUTTON_RELEASE:
			event := transmute(ButtonReleaseEvent)generic_event
			on_cell_clicked(event.event_x, event.event_y, scene)
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

on_cell_clicked :: proc(x: u16, y: u16, scene: ^Scene) {
	idx, row, column := locate_entity_by_coordinate(x, y)

	mined := scene.mines[idx]

	if mined {
		scene.displayed_entities[idx] = .Mine_exploded
		// Lose.
		uncover_all_cells(&scene.displayed_entities, &scene.mines, .Mine_exploded)
	} else {
		visited := [ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]bool{}
		uncover_cells_flood_fill(
			row,
			column,
			&scene.displayed_entities,
			&scene.mines,
			&visited,
			&scene.remaining_uncovered_cells_count,
		)

		if scene.remaining_uncovered_cells_count == 0 {
			uncover_all_cells(&scene.displayed_entities, &scene.mines, .Mine_idle)
		}
	}
}

uncover_all_cells :: proc(
	displayed_entities: ^[ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]Entity_kind,
	mines: ^[ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]bool,
	shown_mine: Entity_kind,
) {
	for &entity, i in displayed_entities {
		if mines[i] {
			entity = shown_mine
		} else {
			row, column := idx_to_row_column(i)
			mines_around_count := count_mines_around_cell(row, column, mines[:])
			assert(mines_around_count <= 8)

			entity = cast(Entity_kind)(cast(int)Entity_kind.Uncovered_0 + mines_around_count)
		}
	}
}

uncover_cells_flood_fill :: proc(
	row: int,
	column: int,
	displayed_entities: ^[ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]Entity_kind,
	mines: ^[ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]bool,
	visited: ^[ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]bool,
	remaining_uncovered_cells_count: ^int,
) {
	i := row_column_to_idx(row, column)
	if visited[i] {return}

	visited[i] = true

	// Do not uncover covered mines.
	if mines[i] {return}

	if displayed_entities[i] != .Covered {return}

	// Uncover cell.

	remaining_uncovered_cells_count^ = clamp(remaining_uncovered_cells_count^ - 1, 0, 1 << 32)
	mines_around_count := count_mines_around_cell(row, column, mines[:])
	assert(mines_around_count <= 8)

	displayed_entities[i] =
	cast(Entity_kind)(cast(int)Entity_kind.Uncovered_0 + mines_around_count)

	// Uncover neighbors.

	// Up.
	if !(row == 0) {
		uncover_cells_flood_fill(
			row - 1,
			column,
			displayed_entities,
			mines,
			visited,
			remaining_uncovered_cells_count,
		)
	}

	// Right
	if !(column == (ENTITIES_COLUMN_COUNT - 1)) {
		uncover_cells_flood_fill(
			row,
			column + 1,
			displayed_entities,
			mines,
			visited,
			remaining_uncovered_cells_count,
		)
	}

	// Bottom.
	if !(row == (ENTITIES_ROW_COUNT - 1)) {
		uncover_cells_flood_fill(
			row + 1,
			column,
			displayed_entities,
			mines,
			visited,
			remaining_uncovered_cells_count,
		)
	}

	// Left.
	if !(column == 0) {
		uncover_cells_flood_fill(
			row,
			column - 1,
			displayed_entities,
			mines,
			visited,
			remaining_uncovered_cells_count,
		)
	}
}

idx_to_row_column :: #force_inline proc(i: int) -> (int, int) {
	column := i % ENTITIES_COLUMN_COUNT
	row := i / ENTITIES_ROW_COUNT

	return row, column
}

row_column_to_idx :: #force_inline proc(row: int, column: int) -> int {
	return cast(int)row * ENTITIES_COLUMN_COUNT + cast(int)column
}

count_mines_around_cell :: proc(row: int, column: int, displayed_entities: []bool) -> int {
	// TODO: Pad the border to elide all bound checks?

	up_left :=
		row == 0 || column == 0 \
		? false \
		: displayed_entities[row_column_to_idx(row - 1, column - 1)]
	up := row == 0 ? false : displayed_entities[row_column_to_idx(row - 1, column)]
	up_right :=
		row == 0 || column == (ENTITIES_COLUMN_COUNT - 1) \
		? false \
		: displayed_entities[row_column_to_idx(row - 1, column + 1)]
	right :=
		column == (ENTITIES_COLUMN_COUNT - 1) \
		? false \
		: displayed_entities[row_column_to_idx(row, column + 1)]
	bottom_right :=
		row == (ENTITIES_ROW_COUNT - 1) || column == (ENTITIES_COLUMN_COUNT - 1) \
		? false \
		: displayed_entities[row_column_to_idx(row + 1, column + 1)]
	bottom :=
		row == (ENTITIES_ROW_COUNT - 1) \
		? false \
		: displayed_entities[row_column_to_idx(row + 1, column)]
	bottom_left :=
		column == 0 || row == (ENTITIES_COLUMN_COUNT - 1) \
		? false \
		: displayed_entities[row_column_to_idx(row + 1, column - 1)]
	left := column == 0 ? false : displayed_entities[row_column_to_idx(row, column - 1)]


	return(
		cast(int)up_left +
		cast(int)up +
		cast(int)up_right +
		cast(int)right +
		cast(int)bottom_right +
		cast(int)bottom +
		cast(int)bottom_left +
		cast(int)left \
	)
}

locate_entity_by_coordinate :: proc(win_x: u16, win_y: u16) -> (idx: int, row: int, column: int) {
	column = cast(int)win_x / ENTITIES_WIDTH
	row = cast(int)win_y / ENTITIES_HEIGHT

	idx = row_column_to_idx(row, column)

	return idx, row, column
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

main :: proc() {
	sprite, err := png.load_from_file("sprite.png", {})
	assert(err == nil)
	sprite_data := make([]u8, sprite.height * sprite.width * 4)

	// Convert the image format from the sprite (RGB) into the X11 image format (BGRX).
	for i := 0; i < sprite.height * sprite.width - 3; i += 1 {
		sprite_data[i * 4 + 0] = sprite.pixels.buf[i * 3 + 2] // R -> B
		sprite_data[i * 4 + 1] = sprite.pixels.buf[i * 3 + 1] // G -> G
		sprite_data[i * 4 + 2] = sprite.pixels.buf[i * 3 + 0] // B -> R
		sprite_data[i * 4 + 3] = 0 // pad
	}

	auth_token, _ := load_x11_auth_token()

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
		ENTITIES_COLUMN_COUNT * ENTITIES_WIDTH,
		ENTITIES_ROW_COUNT * ENTITIES_HEIGHT,
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
	scene := Scene {
		window_id                       = window_id,
		gc_id                           = gc_id,
		sprite_pixmap_id                = pixmap_id,
		connection_information          = connection_information,
		sprite_width                    = cast(u16)sprite.width,
		sprite_height                   = cast(u16)sprite.height,
		sprite_data                     = sprite_data,
		remaining_uncovered_cells_count = ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT,
	}
	for &mine in scene.mines {
		mine = rand.uint32() < ((1 << 32) / 4)
		scene.remaining_uncovered_cells_count -= cast(int)mine
	}

	x11_put_image(
		socket,
		scene.sprite_pixmap_id,
		scene.gc_id,
		scene.sprite_width,
		scene.sprite_height,
		0,
		0,
		img_depth,
		scene.sprite_data,
	)

	x11_map_window(socket, window_id)

	wait_for_x11_events(socket, &scene)
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

@(test)
test_count_mines_around_cell :: proc(_: ^testing.T) {
	{
		mines := [ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]bool{}
		mines[row_column_to_idx(0, 0)] = true
		mines[row_column_to_idx(0, 1)] = true
		mines[row_column_to_idx(0, 2)] = true
		mines[row_column_to_idx(1, 2)] = true
		mines[row_column_to_idx(2, 2)] = true
		mines[row_column_to_idx(2, 1)] = true
		mines[row_column_to_idx(2, 0)] = true
		mines[row_column_to_idx(1, 0)] = true

		assert(count_mines_around_cell(1, 1, mines[:]) == 8)
	}
}
