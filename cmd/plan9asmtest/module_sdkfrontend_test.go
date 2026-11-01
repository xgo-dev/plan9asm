package main

import (
	"reflect"
	"testing"
	"time"
)

func TestModuleSDKFrontendUsesBoundedRootPartitions(t *testing.T) {
	cfg := config{Shards: 64, Workers: 2, Timeout: time.Hour, Flags: []string{"-race", "-p=1"}}
	for _, directory := range []string{"gotoolprofile", "internal/sdkfrontend"} {
		pkg := modulePackage{Directory: directory, Package: "example.org/complete/" + directory}
		child := modulePackageConfig(cfg, pkg, 3)
		if moduleOwner(pkg) != 1 || child.fullPackage || child.rootPart != nil ||
			child.Shards != 64 || child.Workers != 2 || child.Timeout != cfg.Timeout ||
			!reflect.DeepEqual(child.Flags, cfg.Flags) {
			t.Fatalf("source/profile package lost bounded complete-root scheduling: %s %+v", directory, child)
		}
	}
	for _, directory := range []string{"sdkfrontend", "internal/sdkfrontend/child", "future/internal/sdkfrontend", "future"} {
		pkg := modulePackage{Directory: directory, Package: "example.org/complete/" + directory}
		child := modulePackageConfig(cfg, pkg, 4)
		if moduleOwner(pkg) != 2 || !child.fullPackage || child.Shards != 1 || child.Workers != 1 ||
			!reflect.DeepEqual(child.Flags, cfg.Flags) || child.Timeout != cfg.Timeout {
			t.Fatalf("remaining package lost one complete unfiltered command: %s %+v", directory, child)
		}
	}
	// An empty package still needs its ordinary unfiltered Go execution.
	pkg := modulePackage{Directory: "internal/sdkfrontend", NoTestFiles: true}
	child := modulePackageConfig(cfg, pkg, 5)
	if !child.fullPackage || !child.noTestFiles || child.Shards != 1 || child.Workers != 1 {
		t.Fatalf("no-test source package acquired synthetic executing shards: %+v", child)
	}
}
