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

package helpers

import (
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ApplyCacheRewrites is the runtime implementation of a resource's
// gen/definitions/*.yaml cache_rewrites list. Each entry is a {from, to} pair of
// paths, both relative to the object as wrapped under the resource's cache
// data_path (see the generator's CacheDataPath): if the value at "from" exists
// and is not JSON null, it is deleted from "from" and re-written (as raw JSON,
// preserving type) at "to".
//
// This function trusts its input: the generator (gen/generator.go) statically
// validates a resource's cache_rewrites before ever emitting a call to this
// function, rejecting any rewrite set where a "to" is an ancestor of its own
// "from" (which would silently drop sibling data under "to" when the whole
// ancestor node is replaced) or where entries overlap (one entry's "to"
// colliding with another's "from", or two entries sharing a "to"). Given an
// unvalidated, unsafe rewrite set, this function does not re-detect those cases
// and will reproduce the same silent data loss the validation exists to
// prevent -- callers other than generated code must apply the same validation
// (see gen/generator.go's validateCacheRewrites) before use.
func ApplyCacheRewrites(body string, rewrites [][2]string) (string, error) {
	var err error
	for _, rw := range rewrites {
		from, to := rw[0], rw[1]
		if val := gjson.Get(body, from); val.Exists() && val.Type != gjson.Null {
			body, err = sjson.Delete(body, from)
			if err != nil {
				return body, err
			}
			body, err = sjson.SetRaw(body, to, val.Raw)
			if err != nil {
				return body, err
			}
		}
	}
	return body, nil
}
