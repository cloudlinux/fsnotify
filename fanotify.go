package fsnotify

import "C"
import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type fanotifyEventInfoHeader struct {
	InfoType uint8
	Pad      uint8
	Len      uint16
}

// fanotifyEventInfoFID represents fanotify_event_info_fid structure (see fanotify man page)
type fanotifyEventInfoFID struct {
	Hdr  fanotifyEventInfoHeader
	Fsid unix.Fsid
	// FileHandle starts here
}

const (
	sizeOfFileHandleHdr        = C.sizeof_uint + C.sizeof_int
	sizeOfFanotifyEventInfoFID = (int)(unsafe.Sizeof(fanotifyEventInfoFID{}))
)

func (f *fanotifyEventInfoFID) GetHandle(n int) (unix.FileHandle, error) {
	fid := f
	// Get pointer to the start of FileHandle
	fileHandlePtr := unsafe.Pointer(uintptr(unsafe.Pointer(fid)) + unsafe.Sizeof(*fid))

	// Check if hdr len exceeds n or has insufficient length
	if int(fid.Hdr.Len) > n || int(fid.Hdr.Len) < sizeOfFanotifyEventInfoFID+sizeOfFileHandleHdr {
		return unix.FileHandle{}, fmt.Errorf(
			"GetHandle: out of bounds. Expected size n: %v, fid.Hdr.Len: %v",
			n,
			fid.Hdr.Len,
		)
	}
	// The length of the buffer can be calculated from the Header's Len field
	// Subtract the size of the header to get the FileHandle buffer length
	bufferLen := int(fid.Hdr.Len) - sizeOfFanotifyEventInfoFID
	// Create a slice from the pointer
	buf := unsafe.Slice((*byte)(fileHandlePtr), bufferLen)

	// Get size and type of file_handle
	size := uint(*(*C.uint)(unsafe.Pointer(&buf[0])))
	typ := int32(*(*C.int)(unsafe.Pointer(&buf[C.sizeof_uint])))

	// Check if file_handle size is in bounds of n
	bufferLen = sizeOfFanotifyEventInfoFID + sizeOfFileHandleHdr + int(size)
	if bufferLen > n {
		return unix.FileHandle{}, fmt.Errorf(
			"GetHandle: out of bounds. Expected size: %v, actual size: %v",
			n,
			bufferLen,
		)
	}

	return unix.NewFileHandle(typ, buf[sizeOfFileHandleHdr:sizeOfFileHandleHdr+int(size)]), nil
}

func getPathFromHandle(mountFd int, handle unix.FileHandle) (string, error) {
	fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_PATH)
	if err != nil {
		return "", fmt.Errorf("open_by_handle_at failed: %v", err)
	}
	defer unix.Close(fd)

	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	path := make([]byte, unix.PathMax)

	n, err := unix.Readlink(procPath, path)
	if err != nil {
		return "", fmt.Errorf("readlink failed: %v", err)
	}

	return string(path[:n]), nil
}

type FanotifyWatcher struct {
	Fd       int
	mountFd  int
	root     string
	done     chan struct{} // Channel for sending a "quit message" to the reader goroutine
	doneResp chan struct{} // Channel to respond to Close
	Events   chan Event
	Errors   chan error
	poller   *FdPoller
}

func NewFanotifyWatcher(flags, eventFFlags uint, root string) (*FanotifyWatcher, error) {
	fd, err := unix.FanotifyInit(flags, eventFFlags)
	if fd < 0 {
		return nil, err
	}

	poller, err := NewFdPoller(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	fw := &FanotifyWatcher{
		Fd:       fd,
		done:     make(chan struct{}),
		doneResp: make(chan struct{}),
		Events:   make(chan Event),
		Errors:   make(chan error),
		poller:   poller,
		root:     root,
	}
	go fw.readEvents()
	return fw, nil
}

func (fw *FanotifyWatcher) Add(path string, mask uint64, flags uint) error {
	flags |= unix.FAN_MARK_ADD
	err := unix.FanotifyMark(
		fw.Fd,
		flags,
		mask,
		unix.AT_FDCWD,
		path,
	)
	if err != nil {
		log.Printf("unix.FanotifyMark(%d, flags=%s|%d, mask=%d, AT_FDCWD, %s) failed: %s\n", fw.Fd,
			"FAN_MARK_ADD", flags, mask,
			path, err.Error())
		return err
	}
	// Open/Refresh mountFd
	if len(fw.root) > 0 {
		mountFd, err := unix.Open(fw.root, unix.O_RDONLY, 0)
		if err != nil {
			log.Printf("Failed to get mount_fd of %v: %v", fw.root, err)
			return err
		} else {
			fw.mountFd = mountFd
		}
	}
	return nil
}

func (fw *FanotifyWatcher) readEvents() {
	var (
		buf   [unix.FAN_EVENT_METADATA_LEN * 4096]byte // Buffer for a maximum of 4096 raw events
		n     int                                      // Number of bytes read with read()
		errno error                                    // Syscall errno
		ok    bool                                     // For poller.wait
	)

	defer close(fw.doneResp)
	defer close(fw.Errors)
	defer close(fw.Events)
	defer unix.Close(fw.Fd)
	defer fw.poller.Close()
	defer unix.Close(fw.mountFd)

	for {
		// See if we have been closed.
		if fw.isClosed() {
			return
		}

		ok, errno = fw.poller.Wait()
		if errno != nil {
			select {
			case fw.Errors <- errno:
			case <-fw.done:
				return
			}
			continue
		}

		if !ok {
			continue
		}

		n, errno = unix.Read(fw.Fd, buf[:])
		// If a signal interrupted execution, see if we've been asked to close, and try again.
		// http://man7.org/linux/man-pages/man7/signal.7.html :
		if errno == unix.EINTR {
			continue
		}

		// unix.Read might have been woken up by Close. If so, we're done.
		if fw.isClosed() {
			return
		}

		if n < unix.FAN_EVENT_METADATA_LEN {
			var err error
			if n == 0 {
				// If EOF is received. This should really never happen.
				err = io.EOF
			} else if n < 0 {
				// If an error occurred while reading.
				err = errno
			} else {
				// Read was too short.
				err = errors.New("notify: short read in readEvents()")
			}
			select {
			case fw.Errors <- err:
			case <-fw.done:
				return
			}
			continue
		}

		var offset uint32
		for offset <= uint32(n-unix.FAN_EVENT_METADATA_LEN) {
			raw := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset]))
			if !(raw.Event_len >= unix.FAN_EVENT_METADATA_LEN && raw.Event_len <= uint32(n)-offset) {
				continue
			}

			mask := raw.Mask
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				select {
				case fw.Errors <- ErrEventOverflow:
				case <-fw.done:
					return
				}
			}
			if raw.Fd == unix.FAN_NOFD {
				fileHandleOffset := int(offset) + int(raw.Metadata_len)
				if int(raw.Metadata_len)+sizeOfFanotifyEventInfoFID > int(raw.Event_len) {
					offset += raw.Event_len
					continue
				}
				// Get FID info
				info := (*fanotifyEventInfoFID)(unsafe.Pointer(&buf[fileHandleOffset]))
				if info.Hdr.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
					handle, err := info.GetHandle(int(raw.Event_len) - int(raw.Metadata_len))
					if err != nil {
						select {
						case fw.Errors <- err:
						case <-fw.done:
							return
						}
						offset += raw.Event_len
						continue
					}
					path, err := getPathFromHandle(fw.mountFd, handle)
					if err != nil {
						if !errors.Is(unix.ESTALE, err) {
							select {
							case fw.Errors <- err:
							case <-fw.done:
								return
							}
						}
					} else {
						fw.Events <- newFanotifyFIDEvent(path, mask)
					}
				}
			} else {
				path, errno := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", raw.Fd))
				if errno != nil {
					select {
					case fw.Errors <- errno:
					case <-fw.done:
						return
					}
				}

				fw.Events <- newFanotifyEvent(path, uintptr(raw.Fd))
			}
			offset += raw.Event_len
		}
	}
}

func (fw *FanotifyWatcher) isClosed() bool {
	select {
	case <-fw.done:
		return true
	default:
		return false
	}
}

func newFanotifyEvent(name string, fd uintptr) Event {
	return Event{Name: name, Op: Write, File: os.NewFile(fd, name)}
}

func newFanotifyFIDEvent(name string, mask uint64) Event {
	e := Event{Name: name, File: nil}
	if mask&unix.FAN_MODIFY == unix.FAN_MODIFY || mask&unix.FAN_CLOSE_WRITE == unix.FAN_CLOSE_WRITE {
		e.Op |= Write
	}
	if mask&unix.FAN_MOVE_SELF == unix.FAN_MOVE_SELF || mask&unix.FAN_MOVE == unix.FAN_MOVE ||
		mask&unix.FAN_MOVED_TO == unix.FAN_MOVED_TO || mask&unix.FAN_MOVED_FROM == unix.FAN_MOVED_FROM {
		e.Op |= Move
	}
	return e
}

func (fw *FanotifyWatcher) Close() error {
	if fw.isClosed() {
		return nil
	}

	// Send 'close' signal to goroutine, and set the Watcher to closed.
	close(fw.done)

	// Wake up goroutine
	_ = fw.poller.Wake()

	// Wait for goroutine to close
	<-fw.doneResp

	return nil
}
