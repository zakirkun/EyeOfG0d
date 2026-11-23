//go:build !linux

package main

import (
	"context"
	"errors"
)

// unsupportedDriver is the fail-closed driver for non-Linux hosts. The real
// runtime is QEMU plus /dev/kvm, so there is nothing honest to do here: every
// readiness path returns an error and the supervisor reports `failed`.
//
// This exists so the sidecar's state machine and its tests are platform
// independent. It must never be used to claim emulator support.
type unsupportedDriver struct{}

func newAndroidDriver(string) driver { return unsupportedDriver{} }

func (unsupportedDriver) KVM(context.Context) error {
	return errors.New(reasonHost)
}

func (unsupportedDriver) CreateAVD(context.Context, string) (taskAVD, error) {
	return taskAVD{}, errors.New(reasonHost)
}

func (unsupportedDriver) Start(context.Context, taskAVD) (process, error) {
	return nil, errors.New(reasonHost)
}

func (unsupportedDriver) Ready(context.Context) error { return errors.New(reasonHost) }

func (unsupportedDriver) Shutdown(context.Context, process) error { return nil }

// Dynamic operations stay fail-closed off Linux: they report the same host
// requirement rather than pretending an emulator exists.
func (unsupportedDriver) Install(context.Context, string) (OpResult, error) {
	return OpResult{}, errors.New(reasonHost)
}

func (unsupportedDriver) Launch(context.Context, LaunchRequest) (OpResult, error) {
	return OpResult{}, errors.New(reasonHost)
}

func (unsupportedDriver) Logs(context.Context, string, int) (OpResult, error) {
	return OpResult{}, errors.New(reasonHost)
}

func (unsupportedDriver) Packages(context.Context) (OpResult, error) {
	return OpResult{}, errors.New(reasonHost)
}

func (unsupportedDriver) RemoveAVD(string) error { return nil }

func (unsupportedDriver) Reap(context.Context) {}
