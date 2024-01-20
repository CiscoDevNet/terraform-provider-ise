// Copyright © 2023 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Mozilla Public License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mozilla.org/MPL/2.0/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: MPL-2.0

//go:build ignore

package main

import (
	"fmt"
	"os"

	"github.com/pb33f/libopenapi"
)

const (
	modelFile     = "./gen/models/ise_320p4_ers.json"
	outputFile    = "./gen/definition/active_directory.yaml"
	endpoint      = "/activedirectory/"
	schemaElement = "ERSActiveDirectory"
)

func main() {
	modelBytes, err := os.ReadFile(modelFile)
	if err != nil {
		panic(fmt.Sprintf("Error reading file: %v", err))
	}

	document, err := libopenapi.NewDocument(modelBytes)
	if err != nil {
		panic(fmt.Sprintf("Cannot create new document: %e", err))
	}

	docModel, errors := document.BuildV3Model()
	if len(errors) > 0 {
		for i := range errors {
			fmt.Printf("error: %e\n", errors[i])
		}
		panic(fmt.Sprintf("Cannot create v3 model from document: %d errors reported", len(errors)))
	}

	schema, _ := docModel.Model.Components.Schemas.Get(schemaElement)

	prop, _ := schema.Schema().Properties.Get("domain")

	println(prop)

	// write to output file
	// f, err := os.Create(outputFile)
	// if err != nil {
	// 	log.Fatalf("Error creating output file: %v", err)
	// }
	// f.Write(output.Bytes())
}
