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
	"encoding/csv"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type STR struct {
	Repeat1 int
	Repeat2 int
}

type CODIS struct {
	Loci [13]STR
}

var STRMarkers = [13]string{"D3S1358", "vWA", "FGA", "D8S1179", "D21S11", "D18S51",
	"D5S818", "D13S317", "D7S820", "D16S539", "THO1", "TPOX", "CSF1PO"}

const App_id_SearchPerson = auxiliary.Seg_num + 1

// Show the string representations of the CODIS
func (cod *CODIS) Decode2String() []string {
	res := make([]string, 13)
	for i := 0; i < 13; i++ {
		res[i] = STRMarkers[i] + " " + strconv.Itoa(cod.Loci[i].Repeat1) + " " + strconv.Itoa(cod.Loci[i].Repeat2)
	}
	return res
}

// Generate Random CODIS
func GenRandomCODIS() (cod CODIS) {
	for i := 0; i < 13; i++ {
		cod.Loci[i].Repeat1 = rand.Intn(256)
		cod.Loci[i].Repeat2 = rand.Intn(256)
	}
	return
}

// Generate Random CODIS Data, then save it
func GenAndSaveCODISData() {
	dicpath := auxiliary.ReadPath()
	now := time.Now()

	os.Mkdir(dicpath+"/CODIS_Data/", os.ModePerm)
	Indivs := auxiliary.ReadIndividuals()

	R_Data := make([][]string, len(Indivs))

	for i := 0; i < len(Indivs); i++ {
		temp := GenRandomCODIS()
		R_Data[i] = temp.Decode2String()
	}

	file_name := "Random_CODIS_Data.csv"
	file_path := dicpath + "/CODIS_Data/" + file_name
	f, _ := os.Create(file_path)
	w := csv.NewWriter(f)

	w.WriteAll(R_Data)
	w.Flush()
	f.Close()

	fmt.Printf("Finish Generate and Save Random CODIS of "+strconv.Itoa(len(Indivs))+" Individuals in (%s)\n", time.Since(now))

}

// Read the CODIS Data
func ReadCODISData() []CODIS {
	dicpath := auxiliary.ReadPath()
	Indivs := auxiliary.ReadIndividuals()

	path, _ := filepath.Abs(dicpath + "/CODIS_Data/Random_CODIS_Data.csv")

	file, _ := os.Open(path)
	defer file.Close()

	res := make([]CODIS, len(Indivs))

	r := csv.NewReader(file)

	for i := 0; i < len(Indivs); i++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}

		for j := 0; j < 13; j++ {
			temp := strings.Split(row[j], " ")
			res[i].Loci[j].Repeat1, _ = strconv.Atoi(temp[1])
			res[i].Loci[j].Repeat2, _ = strconv.Atoi(temp[2])
		}
	}
	return res
}

func GetCODISbyID(ID int) CODIS {
	raw_enc_codis := ReadCODISData()
	query_cod := raw_enc_codis[ID]

	return query_cod
}
