// Copyright 2017 Pascal de Bruijn. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package totp

import "time"
import "hash"
import "github.com/pmjdebruijn/hotp"

func Value(h func() hash.Hash, secret []byte, time time.Time, length int) string {
  return hotp.Value(h, secret, uint64(time.Unix()) / 30, length)
}

func Match(h func() hash.Hash, secret []byte, time time.Time, length int, leeway int, token string) bool {
  return hotp.Match(h, secret, uint64(time.Unix()) / 30, length, leeway, token)
}
