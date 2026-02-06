package daemon

import (
	_ "embed"
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/app.js
var appJS []byte

//go:embed static/styles.css
var stylesCSS []byte
