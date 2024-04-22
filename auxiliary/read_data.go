package auxiliary

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
)

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

// Read all Individual names
func ReadIndividuals() []string {
	Individuals := []string{}
	path, _ := filepath.Abs("../../../Individuals/Individuals.txt")
	file, _ := os.Open(path)
	defer file.Close()

	br := bufio.NewReader(file)
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		Individuals = append(Individuals, string(a))
	}
	return Individuals
}

// Read All plaintext data
func ReadPlaintext_data(Indivname string) ([]int, []int) {
	rsID := []int{}
	genotype := []int{}

	path, _ := filepath.Abs("../../../Plaintext_Data/" + Indivname + ".csv")
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
