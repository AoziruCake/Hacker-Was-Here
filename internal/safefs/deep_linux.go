//go:build linux

package safefs

import (
	"context"
	"errors"
	"io"
	"strings"
)

const deepEntries = 200000
const deepDepth = 64

// VisitDeep traverses the whole root breadth-first while retaining the same
// protected pin, directory reacquisition, queue, path and FD bounds as quick.
// Callback names are root-relative raw bytes and callbacks must not reenter Root.
func (r *Root) VisitDeep(ctx context.Context, budget *ReadBudget, selectBody func(Entry) bool, visit func(Entry) error) (count int, states []Origin, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := &quickOrigin{Origin: Origin{Path: ".", MaxDepth: deepDepth, Status: "running"}, started: true}
	o.queue = append(o.queue, directoryTask{".", 0, r.initial})
	qCount, qBytes := 1, 1
	defer func() {
		if o.file != nil {
			if o.file.Close() != nil {
				err = ErrInvariant
			}
			o.file = nil
		}
		if o.Status == "running" {
			o.Status = "incomplete"
		}
		states = []Origin{o.Origin}
		if budget != nil {
			budget.ceiling = 0
		}
	}()
	if r.fd < 0 || budget == nil || (budget.Limit != 0 && budget.Limit != MaxDeepTotalRead) {
		return 0, nil, ErrInvariant
	}
	budget.Limit = MaxDeepTotalRead
	if err = ctx.Err(); err != nil {
		return
	}
	if err = r.revalidateRoot(); err != nil {
		return
	}
	limit := func(reason string) error {
		o.Status = "incomplete"
		return visit(Entry{Name: o.Path, Reason: "budget:" + reason})
	}
	for {
		if err = ctx.Err(); err != nil {
			return
		}
		if err = r.revalidateRoot(); err != nil {
			return
		}
		if o.file == nil {
			if len(o.queue) == 0 {
				if o.Status == "running" {
					o.Status = "completed"
				}
				return
			}
			o.active = o.queue[0]
			o.queue[0] = directoryTask{}
			o.queue = o.queue[1:]
			qCount--
			qBytes -= len(o.active.path)
			o.file, err = r.openDirectory(o.active)
			if errors.Is(err, ErrPermission) {
				o.Status = "incomplete"
				if err = visit(Entry{Name: o.active.path, Reason: "permission_denied"}); err != nil {
					return
				}
				continue
			}
			if err != nil {
				return
			}
		}
		if err = r.checkDirectory(o); err != nil {
			return
		}
		if count == deepEntries {
			err = ErrEntryLimit
			return
		}
		names, readErr := o.file.Readdirnames(min(256, deepEntries-count))
		if readErr != nil && readErr != io.EOF {
			err = classify(readErr)
			return
		}
		count += len(names)
		o.EnumeratedEntries += len(names)
		for _, name := range names {
			if err = ctx.Err(); err != nil {
				return
			}
			if !relativeOK(name) || strings.Contains(name, "/") {
				err = ErrInvariant
				return
			}
			path := name
			if o.active.path != "." {
				path = o.active.path + "/" + name
			}
			if len(path) >= 4096 {
				if err = limit("path_bytes"); err != nil {
					return
				}
				continue
			}
			var e Entry
			e, err = r.childEntry(ctx, path, budget, selectBody)
			o.ReadBytes = budget.Used
			if err != nil {
				return
			}
			if e.Kind == "directory" {
				childDepth := o.active.depth + 1
				if childDepth >= deepDepth {
					e.Reason = "depth_limit"
				} else if qCount >= queuedPaths || qBytes+len(path) > queuedBytes {
					e.Reason = "budget:queued_paths"
					if qBytes+len(path) > queuedBytes {
						e.Reason = "budget:queued_bytes"
					}
					o.Status = "incomplete"
				} else {
					o.queue = append(o.queue, directoryTask{path, childDepth, e.version})
					qCount++
					qBytes += len(path)
					e.Reason = ""
				}
			}
			if err = visit(e); err != nil {
				return
			}
			if e.BodyError != nil && !errors.Is(e.BodyError, ErrPermission) && !errors.Is(e.BodyError, ErrLimit) {
				err = e.BodyError
				return
			}
			if e.Reason == "permission_denied" || errors.Is(e.BodyError, ErrPermission) {
				o.Status = "incomplete"
			}
		}
		if err = r.checkDirectory(o); err != nil {
			return
		}
		if readErr == io.EOF {
			if o.file.Close() != nil {
				o.file = nil
				err = ErrInvariant
				return
			}
			o.file = nil
		}
	}
}
