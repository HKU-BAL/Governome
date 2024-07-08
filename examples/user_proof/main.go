package main

import (
	"Governome/auxiliary"
	"Governome/snarks"
	"flag"
)

func GenProof(rsid string, user_name string, keyholderID int, option bool) {
	Indivs := auxiliary.ReadIndividuals()
	var people auxiliary.People
	for i := 0; i < len(Indivs); i++ {
		if Indivs[i].Name == user_name {
			people = Indivs[i]
			break
		}
	}
	snarks.UserProof(false, people, keyholderID, auxiliary.SegmentID(people, auxiliary.RsID_s2i(rsid), auxiliary.Seg_num), option)
}

func GenAllProofForRSID(rsid string, begin, end int, option bool) {
	Indiv := auxiliary.ReadIndividuals()
	for i := begin; i < end; i++ {
		snarks.UserProof(true, Indiv[i], 1, auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num), option)
		snarks.UserProof(true, Indiv[i], 2, auxiliary.SegmentID(Indiv[i], auxiliary.RsID_s2i(rsid), auxiliary.Seg_num), option)
	}
}

func GenAllProofForSpecificAPPID(appid int, begin, end int, option bool) {
	Indiv := auxiliary.ReadIndividuals()
	for i := begin; i < end; i++ {
		snarks.UserProof(true, Indiv[i], 1, appid, option)
		snarks.UserProof(true, Indiv[i], 2, appid, option)
	}
}

func main() {
	rsid := flag.String("rsid", "rs6053810", "Target Site in rsID")
	Username := flag.String("user", "HG00096", "User Name in 1kGP")
	keyholderID := flag.Int("id", 1, "1 or 2, 1 for owners, 2 for hospitals")
	appid := flag.Int("segID", -1, "AppID or SegID for all individual")
	begin := flag.Int("begin", 0, "Begin ID when generate all")
	end := flag.Int("end", 2504, "Begin ID when generate all")
	Genall := flag.Bool("all", false, "Whether include all Individuals")
	Hosted := flag.Bool("precomputed", false, "Whether owner choose to precompute the access token")

	flag.Parse()
	if *Genall {
		if *appid > 0 {
			GenAllProofForSpecificAPPID(*appid%auxiliary.Seg_num, *begin, *end, *Hosted)
		} else {
			GenAllProofForRSID(*rsid, *begin, *end, *Hosted)
		}
	} else {
		GenProof(*rsid, *Username, *keyholderID, *Hosted)
	}
}
