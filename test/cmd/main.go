package main

import (
	"fmt"
	"os"

	"github.com/openshift-eng/openshift-tests-extension/pkg/cmd"

	"github.com/spf13/cobra"

	e "github.com/openshift-eng/openshift-tests-extension/pkg/extension"
	et "github.com/openshift-eng/openshift-tests-extension/pkg/extension/extensiontests"
	g "github.com/openshift-eng/openshift-tests-extension/pkg/ginkgo"

	// Import OTP test package
	_ "gopkg.in/k8snetworkplumbingwg/multus-cni.v4/test/otp"
)

func main() {
	registry := e.NewRegistry()

	ext := e.NewExtension("openshift", "payload", "multus-cni")
	ext.AddSuite(e.Suite{
		Name: "openshift/multus-cni",
		Parents: []string{
			"openshift/conformance/parallel",
		},
		Qualifiers: []string{
			"name.contains('[Suite:openshift/multus-cni]')",
		},
	})

	specs, err := g.BuildExtensionTestSpecsFromOpenShiftGinkgoSuite()
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't build extension test specs from ginkgo: %v\n", err)
		os.Exit(1)
	}

	specs.Walk(func(spec *et.ExtensionTestSpec) {
		spec.Lifecycle = et.LifecycleInforming
	})
	ext.AddSpecs(specs)
	registry.Register(ext)

	root := &cobra.Command{
		Long: "OpenShift Tests Extension for Multus CNI",
	}
	root.AddCommand(cmd.DefaultExtensionCommands(registry)...)

	if err := func() error {
		return root.Execute()
	}(); err != nil {
		os.Exit(1)
	}
}
