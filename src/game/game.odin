package game

import "core:math/rand"
import "core:testing"

TILE_WIDTH :: 16
TILE_HEIGHT :: 16

Position :: struct {
	x: u16,
	y: u16,
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

ASSET_COORDINATES: [Entity_kind]Position = {
	.Uncovered_0 = {x = 0 * 16, y = 22},
	.Uncovered_1 = {x = 1 * 16, y = 22},
	.Uncovered_2 = {x = 2 * 16, y = 22},
	.Uncovered_3 = {x = 3 * 16, y = 22},
	.Uncovered_4 = {x = 4 * 16, y = 22},
	.Uncovered_5 = {x = 5 * 16, y = 22},
	.Uncovered_6 = {x = 6 * 16, y = 22},
	.Uncovered_7 = {x = 7 * 16, y = 22},
	.Uncovered_8 = {x = 8 * 16, y = 22},
	.Covered = {x = 0, y = 38},
	.Mine_exploded = {x = 32, y = 40},
	.Mine_idle = {x = 64, y = 40},
}


ENTITIES_ROW_COUNT :: 16
ENTITIES_COLUMN_COUNT :: 16
ENTITIES_WIDTH :: 16
ENTITIES_HEIGHT :: 16

Scene :: struct {
	window_id:          u32,
	gc_id:              u32,
	sprite_pixmap_id:   u32,
	displayed_entities: [ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]Entity_kind,
	// TODO: Bitfield?
	mines:              [ENTITIES_ROW_COUNT * ENTITIES_COLUMN_COUNT]bool,
}


reset :: proc(scene: ^Scene) {
	for &entity in scene.displayed_entities {
		entity = .Covered
	}

	for &mine in scene.mines {
		mine = rand.choice([]bool{true, false, false, false})
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
		uncover_cells_flood_fill(row, column, &scene.displayed_entities, &scene.mines, &visited)

		// Win.
		if count_remaining_goals(scene.displayed_entities, scene.mines) == 0 {
			uncover_all_cells(&scene.displayed_entities, &scene.mines, .Mine_idle)
		}
	}
}

count_remaining_goals :: proc(
	displayed_entities: [ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]Entity_kind,
	mines: [ENTITIES_COLUMN_COUNT * ENTITIES_ROW_COUNT]bool,
) -> int {

	covered := 0

	for entity in displayed_entities {
		covered += cast(int)(entity == .Covered)
	}

	mines_count := 0

	for mine in mines {
		mines_count += cast(int)mine
	}

	return covered - mines_count
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
) {
	i := row_column_to_idx(row, column)
	if visited[i] {return}

	visited[i] = true

	// Do not uncover covered mines.
	if mines[i] {return}

	if displayed_entities[i] != .Covered {return}

	// Uncover cell.

	mines_around_count := count_mines_around_cell(row, column, mines[:])
	assert(mines_around_count <= 8)

	displayed_entities[i] =
	cast(Entity_kind)(cast(int)Entity_kind.Uncovered_0 + mines_around_count)

	// Uncover neighbors.

	// Up.
	if !(row == 0) {
		uncover_cells_flood_fill(row - 1, column, displayed_entities, mines, visited)
	}

	// Right
	if !(column == (ENTITIES_COLUMN_COUNT - 1)) {
		uncover_cells_flood_fill(row, column + 1, displayed_entities, mines, visited)
	}

	// Bottom.
	if !(row == (ENTITIES_ROW_COUNT - 1)) {
		uncover_cells_flood_fill(row + 1, column, displayed_entities, mines, visited)
	}

	// Left.
	if !(column == 0) {
		uncover_cells_flood_fill(row, column - 1, displayed_entities, mines, visited)
	}
}

idx_to_row_column :: #force_inline proc(i: int) -> (int, int) {
	column := i % ENTITIES_COLUMN_COUNT
	row := i / ENTITIES_ROW_COUNT

	return row, column
}

row_column_to_idx :: #force_inline proc(row: int, column: int) -> int {
	return row * ENTITIES_COLUMN_COUNT + column
}

count_mines_around_cell :: proc(row: int, column: int, displayed_entities: []bool) -> int {
	// TODO: Pad the border to elide all bound checks?

	up_left :=
		row == 0 || column == 0 ? false : displayed_entities[row_column_to_idx(row - 1, column - 1)]
	up := row == 0 ? false : displayed_entities[row_column_to_idx(row - 1, column)]
	up_right :=
		row == 0 || column == (ENTITIES_COLUMN_COUNT - 1) ? false : displayed_entities[row_column_to_idx(row - 1, column + 1)]
	right :=
		column == (ENTITIES_COLUMN_COUNT - 1) ? false : displayed_entities[row_column_to_idx(row, column + 1)]
	bottom_right :=
		row == (ENTITIES_ROW_COUNT - 1) || column == (ENTITIES_COLUMN_COUNT - 1) ? false : displayed_entities[row_column_to_idx(row + 1, column + 1)]
	bottom :=
		row == (ENTITIES_ROW_COUNT - 1) ? false : displayed_entities[row_column_to_idx(row + 1, column)]
	bottom_left :=
		column == 0 || row == (ENTITIES_COLUMN_COUNT - 1) ? false : displayed_entities[row_column_to_idx(row + 1, column - 1)]
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
