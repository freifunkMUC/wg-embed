//go:build !linux

package wgembed

import "github.com/sirupsen/logrus"

// syncRoutes does nothing outside Linux: the routing table is set up with
// netlink, and the platforms without it are development environments, where
// the interface is not carrying anybody's traffic.
func (wg *commonInterface) syncRoutes() error {
	if wg.manageRoutes {
		logrus.Debug("ManageRoutes is set, but routes are only managed on Linux")
	}
	return nil
}
