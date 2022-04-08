//go:build !windows
// +build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

// modified from https://git.zx2c4.com/wireguard-go

package wgembed

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// userspaceInterface represents an userspace wireguard-go
// network interface
type userspaceInterface struct {
	commonInterface
	device *device.Device
	uapi   net.Listener
}

func newUserspaceInterface(interfaceName string) (WireGuardInterface, error) {
	wg := &userspaceInterface{
		commonInterface: commonInterface{
			name: interfaceName,
		},
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wg client")
	}
	wg.client = client

	tunDevice, err := tun.CreateTUN(wg.name, device.DefaultMTU)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TUN device")
	}

	// open UAPI file (or use supplied fd)
	fileUAPI, err := ipc.UAPIOpen(wg.name)
	if err != nil {
		return nil, errors.Wrap(err, "UAPI listen error")
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", interfaceName))
	wg.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	errs := make(chan error)

	uapi, err := ipc.UAPIListen(wg.name, fileUAPI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to listen on uapi socket")
	}
	wg.uapi = uapi

	go func() {
		for {
			connection, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go wg.device.IpcHandle(connection)
		}
	}()

	return wg, nil
}

// Wait will return a channel that signals when the
// wireguard interface is stopped
func (wg *userspaceInterface) Wait() chan struct{} {
	return wg.device.Wait()
}

// Close will stop and clean up both the wireguard
// interface and userspace configuration api
func (wg *userspaceInterface) Close() error {
	if err := wg.uapi.Close(); err != nil {
		return err
	}
	wg.device.Close()
	wg.client.Close()
	return nil
}
