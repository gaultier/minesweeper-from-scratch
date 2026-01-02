#+build !wasm32
package main

import "x11"

main :: proc() {
	x11.run()
}
