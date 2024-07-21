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

package auxiliary

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
)

type People struct {
	Name string
	ID   int
}

// Get the subFolder Name
func MappingPeopletoFolder(people People) string {
	return strconv.Itoa(int(math.Floor(float64(people.ID)/100))*100) + "-" + strconv.Itoa(int(math.Floor(float64(people.ID)/100))*100+99)
}

// genotype string -> Int
func Genotype_s2i(s string) int {
	val1, _ := strconv.Atoi(s[0:1])
	val2, _ := strconv.Atoi(s[2:3])
	return val1*4 + val2
}

// genotype int -> string
func Genotype_i2s(val int) string {
	val2 := val % 4
	val1 := (val - val2) / 4
	s1 := strconv.Itoa(val1)
	s2 := strconv.Itoa(val2)
	s := s1 + "|" + s2
	return s
}

// rsID -> select and remove "rs"
func RsID_s2i(s string) int {
	if len(s) < 2 {
		return -1
	}
	if s[0:2] != "rs" {
		return -1
	}
	val, _ := big.NewInt(1).SetString(s[2:], 0)
	res := int(val.Int64())
	return res
}

// rsID -> int to string, add "rs"
func RsID_i2s(val int) string {
	str := strconv.Itoa(val)
	return "rs" + str
}

// Generate a file to show the root path
func SavePath(dicpath string) {
	f, _ := os.Create("../../defaultPath")
	w := csv.NewWriter(f)

	pathstring := make([][]string, 1)
	pathstring[0] = make([]string, 1)
	pathstring[0][0] = dicpath

	w.WriteAll(pathstring)

	w.Flush()
	f.Close()
}

// Read the root path from the file
func ReadPath() string {
	var dicpath string
	path, _ := filepath.Abs("../../defaultPath")
	file, _ := os.Open(path)
	defer file.Close()

	r := csv.NewReader(file)
	for {
		row, err := r.Read()
		if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		}
		if err == io.EOF {
			break
		}

		dicpath = row[0]

	}
	return dicpath
}

// Read all Individual names
func ReadIndividuals() []People {
	dicpath := ReadPath()
	Individuals := make([]People, 0)
	path, _ := filepath.Abs(dicpath + "/Individuals/Individuals.csv")
	file, _ := os.Open(path)
	defer file.Close()

	r := csv.NewReader(file)
	for {
		row, err := r.Read()
		if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		}
		if err == io.EOF {
			break
		}

		var p People
		p.Name = row[0]
		p.ID, _ = strconv.Atoi(row[1])
		Individuals = append(Individuals, p)

	}
	return Individuals
}

// Read All plaintext data
func ReadPlaintext_data(people People) ([]int, []int) {
	dicpath := ReadPath()
	rsID := []int{}
	genotype := []int{}

	path, _ := filepath.Abs(dicpath + "/Plaintext_Data/" + MappingPeopletoFolder(people) + "/" + people.Name + ".csv")
	file, _ := os.Open(path)
	defer file.Close()

	r := csv.NewReader(file)
	for {
		row, err := r.Read()
		if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		}
		if err == io.EOF {
			break
		}

		if RsID_s2i(row[0]) == -1 {
			continue
		}
		rsID = append(rsID, RsID_s2i(row[0]))
		genotype = append(genotype, Genotype_s2i(row[1]))

	}

	return rsID, genotype
}

// Query a specific snp in plaintext
func QueryPlaintextByrsID(rsid int, genotype int, DataLen int) int {
	Indiv := ReadIndividuals()

	if DataLen == 0 {
		DataLen = len(Indiv)
	}

	count := 0

	for i := 0; i < DataLen; i++ {
		rsIDs, GenoTypes := ReadPlaintext_data(Indiv[i])
		for j := 0; j < len(rsIDs); j++ {
			if rsIDs[j] == rsid && GenoTypes[j] == genotype {
				count++
				break
			}
		}

	}

	fmt.Println(strconv.Itoa(count) + " Individuals of " + strconv.Itoa(DataLen) + " have Variant " + RsID_i2s(rsid) + " " + Genotype_i2s(genotype))

	return count
}
