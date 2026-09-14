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
	"os"

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
	device   *device.Device
	uapi     net.Listener
	uapiFile *os.File
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

	tunDevice, err := tun.CreateTUN(wg.name, device.DefaultMTU)
	if err != nil {
		_ = client.Close()
		return nil, errors.Wrap(err, "failed to create TUN device")
	}

	// open UAPI file (or use supplied fd)
	fileUAPI, err := ipc.UAPIOpen(wg.name)
	if err != nil {
		_ = tunDevice.Close()
		_ = client.Close()
		return nil, errors.Wrap(err, "UAPI listen error")
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", interfaceName))
	// from here on the device owns tunDevice and closes it
	wg.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	uapi, err := ipc.UAPIListen(wg.name, fileUAPI)
	if err != nil {
		_ = fileUAPI.Close()
		wg.device.Close()
		_ = client.Close()
		return nil, errors.Wrap(err, "failed to listen on uapi socket")
	}
	wg.client = client
	wg.uapi = uapi
	// UAPIListen works on its own copy of the descriptor (net.FileListener),
	// so ours has to be closed as well - but only in Close, after the
	// listener. Closing it right here made wireguard-go's watcher on the socket
	// path shut down its cancel pipe, and closing the listener later failed
	// with "file already closed".
	wg.uapiFile = fileUAPI

	go func() {
		for {
			connection, err := uapi.Accept()
			if err != nil {
				// the listener was closed; nothing is left to serve
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
// interface and userspace configuration api. It always releases everything,
// even when one step fails, and calling it again is a no-op.
func (wg *userspaceInterface) Close() error {
	wg.closeOnce.Do(func() {
		wg.closeErr = wg.uapi.Close()
		if err := wg.uapiFile.Close(); err != nil && wg.closeErr == nil {
			wg.closeErr = err
		}
		wg.device.Close()
		if err := wg.client.Close(); err != nil && wg.closeErr == nil {
			wg.closeErr = err
		}
	})
	return wg.closeErr
}
