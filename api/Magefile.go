// +build mage

package main

import "github.com/harwoeck/common-mage/protoh"

func Lint() {
	protoh.Lint()
}

func Breaking() {
	protoh.Breaking()
}

func Generate() {
	protoh.Generate()
}
