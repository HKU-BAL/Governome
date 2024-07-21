// Copyright 2024 The University of Hong Kong, Department of Computer Science
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package applications

import (
	"Governome/auxiliary"
	"bufio"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const App_id_GWAS = auxiliary.Seg_num + 2

// Whether s in set
func Match(s string, set []auxiliary.People) int {
	for _, ss := range set {
		if s == ss.Name {
			return ss.ID
		}
	}
	return -1
}

// Read the example phenotype in Hail
func ReadPhenotype(IndivLimit []auxiliary.People, Population string) ([]auxiliary.People, []int, []int, []int) {
	dicpath := auxiliary.ReadPath()
	Individuals := []auxiliary.People{}
	isFemale := []int{}
	PurpleHair := []int{}
	CaffeineConsumption := []int{}

	path, _ := filepath.Abs(dicpath + "/Phenotype/1kg_annotations.txt")
	file, _ := os.Open(path)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, "\t")

		if fields[0] == "Sample" {
			continue
		}

		match := Match(fields[0], IndivLimit)

		if match == -1 {
			continue
		}

		if fields[2] != Population && Population != "ALL" {
			continue
		}

		var p auxiliary.People
		p.Name = fields[0]
		p.ID = match
		Individuals = append(Individuals, p)
		if fields[3] == "true" {
			isFemale = append(isFemale, 1)
		} else {
			isFemale = append(isFemale, 0)
		}

		if fields[4] == "true" {
			PurpleHair = append(PurpleHair, 1)
		} else {
			PurpleHair = append(PurpleHair, 0)
		}

		val, _ := strconv.Atoi(fields[5])
		if val > 4 {
			val = 1
		} else {
			val = 0
		}
		CaffeineConsumption = append(CaffeineConsumption, val)

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return Individuals, isFemale, PurpleHair, CaffeineConsumption
}
