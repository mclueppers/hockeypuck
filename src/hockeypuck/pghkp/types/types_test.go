/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package types

import (
	stdtesting "testing"

	"golang.org/x/exp/slices"
	gc "gopkg.in/check.v1"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type S struct{}

var _ = gc.Suite(&S{})

func (s *S) TestTSVectorParsing(c *gc.C) {
	// Roundtrip some keywords containing characters special to TSVectors
	kw := []string{
		`didn't, wouldn't, can't`,
		`test`,
		`two\tlines\n`,
	}
	tsv := `'didn''t, wouldn''t, can''t' 'test' 'two\\tlines\\n'`
	kw2 := keywordsFromTSVector(tsv)
	slices.Sort(kw2)
	c.Assert(kw2, gc.DeepEquals, kw)
	tsv2, err := keywordsToTSVector(kw, " ")
	c.Assert(err, gc.IsNil)
	c.Assert(tsv2, gc.Equals, tsv)
}
