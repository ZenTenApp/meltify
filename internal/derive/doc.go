// Package derive replicates the seedify behaviors meltify depends on.
//
// Production code in this package must not import github.com/ZenTenApp/seedify.
// Characterization tests may still call seedify to prove bit-identical output
// until that module is dropped.
package derive
