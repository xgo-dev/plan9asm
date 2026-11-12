package main

import "github.com/xgo-dev/plan9asm/internal/sdkfrontend"

func ordinaryPackageEnvironment(goos, goarch string, input []string) ([]string, error) {
	return sdkfrontend.OrdinaryEnvironment(goos, goarch, input)
}

func featurePackageEnvironment(goos, goarch string, input []string) ([]string, error) {
	return sdkfrontend.FeatureEnvironment(goos, goarch, input)
}

func ordinaryGoEnvFile(requested, actual string) (string, error) {
	return sdkfrontend.GoEnvFile(requested, actual)
}
