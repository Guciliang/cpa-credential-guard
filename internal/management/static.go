package management

import _ "embed"

// staticIndex is intentionally a static shell. It contains no credential,
// proxy, state, token, or management response data.
//
//go:embed web/index.html
var staticIndex []byte
