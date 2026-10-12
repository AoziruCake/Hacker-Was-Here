//go:build !linux

package main

import "context"

func commandContext(parent context.Context) (context.Context, func()) {
	return context.WithCancel(parent)
}
