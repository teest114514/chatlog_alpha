//go:build !darwin

package appver

func (i *Info) initialize() error {
	return nil
}
