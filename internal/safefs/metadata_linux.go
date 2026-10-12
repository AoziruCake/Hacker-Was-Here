//go:build linux

package safefs

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (r *Root) metadata(name string) (_ []byte, err error) {
	fd, err := r.pin(r.selfFD, name, unix.O_RDONLY|unix.O_CLOEXEC, resolveInside)
	if err != nil {
		return nil, metadataFailure(err)
	}
	defer func() {
		if unix.Close(fd) != nil {
			err = ErrInvariant
		}
	}()
	data := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		remaining := (1 << 20) - len(data)
		if remaining == 0 {
			return nil, ErrEnvironment
		}
		take := len(buf)
		if take > remaining {
			take = remaining
		}
		n, readErr := unix.Read(fd, buf[:take])
		if readErr == unix.EINTR {
			continue
		}
		if readErr != nil {
			return nil, metadataFailure(classify(readErr))
		}
		if n == 0 {
			return data, nil
		}
		if len(data)+n > 1<<20 {
			return nil, ErrEnvironment
		}
		data = append(data, buf[:n]...)
	}
}

func noCapabilities(status []byte) error {
	required := map[string]bool{"CapEff:": false, "CapPrm:": false, "CapInh:": false, "CapAmb:": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, ok := required[fields[0]]; !ok {
			continue
		}
		if required[fields[0]] || len(fields) != 2 {
			return ErrEnvironment
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return ErrEnvironment
		}
		if value != 0 {
			return ErrPrivilege
		}
		required[fields[0]] = true
	}
	for _, seen := range required {
		if !seen {
			return ErrEnvironment
		}
	}
	return nil
}

func mountType(data []byte, target snapshot) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(data) > 1<<20 || len(lines) > 8192 {
		return "", ErrEnvironment
	}
	seen := make(map[uint64]bool)
	found := ""
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return "", ErrEnvironment
		}
		id, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || id == 0 || seen[id] {
			return "", ErrEnvironment
		}
		seen[id] = true
		if _, err = strconv.ParseUint(fields[1], 10, 64); err != nil {
			return "", ErrEnvironment
		}
		dev := strings.Split(fields[2], ":")
		if len(dev) != 2 {
			return "", ErrEnvironment
		}
		major, e1 := strconv.ParseUint(dev[0], 10, 32)
		minor, e2 := strconv.ParseUint(dev[1], 10, 32)
		if e1 != nil || e2 != nil {
			return "", ErrEnvironment
		}
		for _, p := range []string{fields[3], fields[4]} {
			if !strings.HasPrefix(p, "/") {
				return "", ErrEnvironment
			}
			for i := 0; i < len(p); i++ {
				if p[i] != '\\' {
					continue
				}
				if i+3 >= len(p) {
					return "", ErrEnvironment
				}
				escape := p[i+1 : i+4]
				if escape != "040" && escape != "011" && escape != "012" && escape != "134" {
					return "", ErrEnvironment
				}
				i += 3
			}
		}
		dash := 6
		for dash < len(fields) && fields[dash] != "-" {
			dash++
		}
		if dash+4 != len(fields) {
			return "", ErrEnvironment
		}
		if id != target.stat.Mnt_id {
			continue
		}
		if uint32(major) != target.stat.Dev_major || uint32(minor) != target.stat.Dev_minor {
			return "", ErrEnvironment
		}
		options := "," + fields[5] + ","
		for _, required := range []string{"ro", "nodev", "nosuid", "noexec"} {
			if !strings.Contains(options, ","+required+",") {
				return "", ErrMount
			}
		}
		if strings.Contains(options, ",rw,") {
			return "", ErrMount
		}
		found = fields[dash+1]
	}
	if found != "ext4" {
		return "", ErrMount
	}
	return found, nil
}
