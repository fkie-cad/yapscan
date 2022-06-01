package procio

// procPath is the path to the /proc pseudo-filesystem
// this should not be touched in production code, but
// can be used during testing in order to provide a
// mock /proc fs.
var procPath = "/proc"
