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
