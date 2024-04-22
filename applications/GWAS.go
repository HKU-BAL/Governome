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
func Match(s string, set []string) bool {
	for _, ss := range set {
		if s == ss {
			return true
		}
	}
	return false
}

func ReadPhenotype(IndivLimit []string, Population string) ([]string, []int, []int, []int) {

	Individuals := []string{}
	isFemale := []int{}
	PurpleHair := []int{}
	CaffeineConsumption := []int{}

	path, _ := filepath.Abs("../../../Phenotype/1kg_annotations.txt")
	file, _ := os.Open(path)
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, "\t")

		if fields[0] == "Sample" {
			continue
		}

		if !Match(fields[0], IndivLimit) {
			continue
		}

		if fields[2] != Population {
			continue
		}

		Individuals = append(Individuals, fields[0])
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
		CaffeineConsumption = append(CaffeineConsumption, val)

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return Individuals, isFemale, PurpleHair, CaffeineConsumption
}
