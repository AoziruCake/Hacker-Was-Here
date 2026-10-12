//go:build linux

package safefs

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const originEntries = 4096
const originBytes = 8 << 20

// Reserve one full returned batch, including maximum-length paths.
const queuedPaths = 4096 - 256 - 12
const queuedBytes = (4 << 20) - 256*4095 - 4096

type Origin struct {
	Path              string `json:"path"`
	MaxDepth          int    `json:"max_depth"`
	Status            string `json:"status"`
	EnumeratedEntries int    `json:"enumerated_entries"`
	ReadBytes         int    `json:"read_bytes"`
}

type directoryTask struct {
	path    string
	depth   int
	version snapshot
}
type quickOrigin struct {
	Origin
	queue   []directoryTask
	active  directoryTask
	file    *os.File
	started bool
}

func quickOrigins() []*quickOrigin {
	paths := []string{".", "etc/motd", "tmp/motd", "tmp/index.html", "root", "home", "srv", "var/www", "var/lib/mysql", "tmp", "var/tmp", "data", "backup", "backups", "opt"}
	var origins []*quickOrigin
	for i, p := range paths {
		depth := 4
		if i == 0 {
			depth = 1
		}
		if i > 0 && i < 4 {
			depth = 0
		}
		origins = append(origins, &quickOrigin{Origin: Origin{Path: p, MaxDepth: depth, Status: "not_started"}})
	}
	return origins
}

// openDirectory only reacquires a protected pin and compares the queued version.
// No pathname is ever opened for directory contents or file contents.
func (r *Root) openDirectory(task directoryTask) (f *os.File, err error) {
	fd := r.fd
	if task.path != "." {
		fd, err = r.pin(r.fd, task.path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, resolveInside)
		if err != nil {
			return nil, err
		}
		defer func() {
			if unix.Close(fd) != nil {
				if f != nil {
					f.Close()
					f = nil
				}
				err = ErrInvariant
			}
		}()
	}
	s, err := r.calls.snapshot(fd)
	if err != nil {
		return nil, err
	}
	if err = r.validateSnapshot(task.version, s); err != nil {
		return nil, err
	}
	readFD, err := r.calls.reopen(r.fdDir, fd, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, classify(err)
	}
	f = os.NewFile(uintptr(readFD), "hwh-quick-directory")
	if f == nil {
		unix.Close(readFD)
		return nil, ErrInvariant
	}
	opened, err := r.calls.snapshot(readFD)
	if err == nil {
		err = r.validateSnapshot(s, opened)
	}
	if err != nil {
		if f.Close() != nil {
			err = ErrInvariant
		}
		return nil, err
	}
	return f, nil
}

func (r *Root) checkDirectory(o *quickOrigin) error {
	if err := r.revalidateRoot(); err != nil {
		return err
	}
	s, err := r.calls.snapshot(int(o.file.Fd()))
	if err != nil {
		return err
	}
	return r.validateSnapshot(o.active.version, s)
}

// VisitQuick serializes bounded, round-robin origin traversal. Callback names
// are root-relative raw bytes. Callbacks must not reenter Root.
func (r *Root) VisitQuick(ctx context.Context, budget *ReadBudget, selectBody func(Entry) bool, visit func(Entry) error) (count int, states []Origin, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	origins := quickOrigins()
	defer func() {
		for _, o := range origins {
			if o.file != nil {
				if o.file.Close() != nil {
					err = ErrInvariant
				}
				o.file = nil
			}
			if o.Status == "running" {
				o.Status = "incomplete"
			}
			states = append(states, o.Origin)
		}
		if budget != nil {
			budget.ceiling = 0
		}
	}()
	if r.fd < 0 || budget == nil {
		return 0, nil, ErrInvariant
	}
	if err = ctx.Err(); err != nil {
		return
	}
	if err = r.revalidateRoot(); err != nil {
		return
	}
	qCount, qBytes := 0, 0
	closeOrigin := func(o *quickOrigin) error {
		for _, t := range o.queue {
			qCount--
			qBytes -= len(t.path)
		}
		o.queue = nil
		if o.file != nil {
			e := o.file.Close()
			o.file = nil
			if e != nil {
				return ErrInvariant
			}
		}
		return nil
	}
	limit := func(o *quickOrigin, reason string) error {
		o.Status = "incomplete"
		return visit(Entry{Name: o.Path, Reason: "budget:" + reason})
	}
	processEntry := func(o *quickOrigin, e *Entry) (originLimit bool, processErr error) {
		originLimit = errors.Is(e.BodyError, ErrReadBudget) && budget.ceiling < MaxTotalRead
		if originLimit {
			e.BodyError = ErrOriginReadBudget
			o.Status = "incomplete"
		}
		if e.Reason == "permission_denied" || errors.Is(e.BodyError, ErrPermission) {
			o.Status = "incomplete"
		}
		if processErr = visit(*e); processErr != nil {
			o.Status = "incomplete"
			return
		}
		if !originLimit && e.BodyError != nil && !errors.Is(e.BodyError, ErrPermission) && !errors.Is(e.BodyError, ErrLimit) {
			o.Status = "incomplete"
			processErr = e.BodyError
		}
		return
	}
	// These explicit paths have a single owner, even when root/tmp enumerate them.
	explicit := map[string]bool{}
	observed := map[string]bool{}
	for _, o := range origins[1:] {
		explicit[o.Path] = true
	}
	for {
		work := false
		for _, o := range origins {
			if o.started && o.file == nil && len(o.queue) == 0 {
				continue
			}
			work = true
			if err = ctx.Err(); err != nil {
				return
			}
			if err = r.revalidateRoot(); err != nil {
				return
			}
			if !o.started {
				o.started = true
				o.Status = "running"
				if o.Path == "." {
					o.queue = append(o.queue, directoryTask{".", 0, r.initial})
					qCount++
					qBytes++
				} else {
					var e Entry
					budget.ceiling = min(MaxTotalRead, budget.Used+originBytes)
					before := budget.Used
					e, err = r.childEntry(ctx, o.Path, budget, selectBody)
					o.ReadBytes += budget.Used - before
					if !observed[o.Path] && (errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)) {
						o.Status = "not_present"
						err = nil
						continue
					}
					if err != nil {
						return
					}
					if o.MaxDepth > 0 && e.Kind == "directory" {
						o.queue = append(o.queue, directoryTask{o.Path, 0, e.version})
						qCount++
						qBytes += len(o.Path)
					} else {
						o.Status = "completed"
						if e.Reason != "" {
							o.Status = "excluded"
						}
						var originLimit bool
						if originLimit, err = processEntry(o, &e); err != nil {
							return
						}
						if originLimit {
							if err = limit(o, "origin_read_bytes"); err != nil {
								return
							}
						}
						continue
					}
				}
			}
			if o.file == nil {
				o.active = o.queue[0]
				o.queue[0] = directoryTask{}
				o.queue = o.queue[1:]
				qCount--
				qBytes -= len(o.active.path)
				o.file, err = r.openDirectory(o.active)
				if errors.Is(err, ErrPermission) {
					o.Status = "incomplete"
					err = visit(Entry{Name: o.active.path, Reason: "permission_denied"})
					if err != nil {
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
			if count == 20000 {
				return count, nil, ErrEntryLimit
			}
			names, readErr := o.file.Readdirnames(min(256, 20000-count, originEntries-o.EnumeratedEntries))
			if readErr != nil && readErr != io.EOF {
				return count, nil, classify(readErr)
			}
			count += len(names)
			o.EnumeratedEntries += len(names)
			for _, name := range names {
				if err = ctx.Err(); err != nil {
					return
				}
				if !relativeOK(name) || strings.Contains(name, "/") {
					return count, nil, ErrInvariant
				}
				path := name
				if o.active.path != "." {
					path = o.active.path + "/" + name
				}
				if len(path) >= 4096 {
					if err = limit(o, "path_bytes"); err != nil {
						return
					}
					continue
				}
				if explicit[path] {
					observed[path] = true
					continue
				}
				// The same shared budget enforces both remaining global and origin bytes.
				budget.ceiling = min(MaxTotalRead, budget.Used+originBytes-o.ReadBytes)
				before := budget.Used
				var e Entry
				e, err = r.childEntry(ctx, path, budget, selectBody)
				o.ReadBytes += budget.Used - before
				if err != nil {
					return
				}
				if e.Kind == "directory" {
					if o.Path == "." {
						e.Reason = "directory_not_scanned"
					} else if o.active.depth+1 >= o.MaxDepth {
						e.Reason = "depth_limit"
					} else if qCount >= queuedPaths || qBytes+len(path) > queuedBytes {
						e.Reason = "budget:queued_paths"
						if qBytes+len(path) > queuedBytes {
							e.Reason = "budget:queued_bytes"
						}
						o.Status = "incomplete"
					} else {
						o.queue = append(o.queue, directoryTask{path, o.active.depth + 1, e.version})
						qCount++
						qBytes += len(path)
						e.Reason = ""
					}
				}
				var originLimit bool
				if originLimit, err = processEntry(o, &e); err != nil {
					return
				}
				if originLimit {
					if err = r.checkDirectory(o); err != nil {
						return
					}
					if err = limit(o, "origin_read_bytes"); err != nil {
						return
					}
					if err = closeOrigin(o); err != nil {
						return
					}
					break
				}
			}
			if o.file == nil {
				continue
			}
			if err = r.checkDirectory(o); err != nil {
				return
			}
			if o.EnumeratedEntries == originEntries {
				if err = limit(o, "origin_entries"); err != nil {
					return
				}
				if err = closeOrigin(o); err != nil {
					return
				}
			} else if readErr == io.EOF {
				if o.file.Close() != nil {
					o.file = nil
					return count, nil, ErrInvariant
				}
				o.file = nil
				if len(o.queue) == 0 && o.Status == "running" {
					o.Status = "completed"
				}
			}
		}
		if !work {
			return
		}
	}
}

var ErrOriginReadBudget = errors.New("origin_read_bytes")
