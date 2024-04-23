package main

import (
	"Governome/auxiliary"
	"Governome/snarks"
	"flag"
)

func GenProof(rsid string, user_name string, keyholderID int) {
	Indivs := auxiliary.ReadIndividuals()
	var people auxiliary.People
	for i := 0; i < len(Indivs); i++ {
		if Indivs[i].Name == user_name {
			people = Indivs[i]
			break
		}
	}
	snarks.UserProof(false, people, keyholderID, auxiliary.SegmentID(people, auxiliary.RsID_s2i(rsid), auxiliary.Seg_num))
}

func GenAllProofForRSID(rsid string, begin, end int) {
	Indiv := auxiliary.ReadIndividuals()
	for i := begin; i < end; i++ {
		snarks.UserProof(true, Indiv[i], 1, auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num))
		snarks.UserProof(true, Indiv[i], 2, auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num))
	}
}

func GenAllProofForSpecificAPPID(appid int, begin, end int) {
	Indiv := auxiliary.ReadIndividuals()
	for i := begin; i < end; i++ {
		snarks.UserProof(true, Indiv[i], 1, appid)
		snarks.UserProof(true, Indiv[i], 2, appid)
	}
}

func main() {
	rsid := flag.String("Rsid", "rs6053810", "Target Site")
	Username := flag.String("User", "HG00096", "User Name")
	keyholderID := flag.Int("ID", 1, "1 or 2, different key custodians")
	appid := flag.Int("APPID", -1, "AppID for all individual")
	begin := flag.Int("begin", 0, "Begin ID when generate all")
	end := flag.Int("end", 2504, "Begin ID when generate all")
	Genall := flag.Bool("All", false, "Whether include all Individuals")
	flag.Parse()
	if *Genall {
		if *appid > 0 {
			GenAllProofForSpecificAPPID(*appid%auxiliary.Seg_num, *begin, *end)
		} else {
			GenAllProofForRSID(*rsid, *begin, *end)
		}
	} else {
		GenProof(*rsid, *Username, *keyholderID)
	}
}
