package trivium

import (
	"Governome/applications"
	"Governome/auxiliary"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sp301415/tfhe-go/tfhe"
)

// Read plaintext data, encrypt it, then save it
func EncryptAndSaveData(batch_size int, option bool) {

	now := time.Now()

	Indivs := auxiliary.ReadIndividuals()

	blockfolder := "BlockSize_" + strconv.Itoa(batch_size)

	os.Mkdir("../../../Segments_Enc_Data_Trivium", os.ModePerm)
	os.Mkdir("../../../Segments_Enc_Data_Trivium/"+blockfolder, os.ModePerm)

	subfoldernum := int(math.Ceil(float64(len(Indivs)) / 100))
	for i := 0; i < subfoldernum; i++ {
		os.Mkdir("../../../Segments_Enc_Data_Trivium/"+blockfolder+"/"+strconv.Itoa(i*100)+"-"+strconv.Itoa(i*100+99), os.ModePerm)
	}

	numCores := runtime.NumCPU()

	var wg sync.WaitGroup
	wg.Add(len(Indivs))

	ch := make(chan struct{}, numCores/2)

	fmt.Println("threads number: " + strconv.Itoa(numCores/2))

	for i := 0; i < len(Indivs); i++ {

		index := i
		ch <- struct{}{}
		go func() {
			Encoded_Variants := DivideIntoSegments(Indivs[index])

			keyinfo1, keyhash1 := GenerateRawKey(Indivs[index], 1)
			keyinfo2, keyhash2 := GenerateRawKey(Indivs[index], 2)

			enc_data := Data_Enc(Encoded_Variants, keyinfo1, keyinfo2, batch_size, option)
			string_data := SegmentToStrings(enc_data, keyhash1, keyhash2, Indivs[index].Name)
			file_name := Indivs[index].Name
			if option {
				file_name = file_name + "_Hosted"
			}
			file_name = file_name + "_Segments.csv"
			file_path := "../../../Segments_Enc_Data_Trivium/" + blockfolder + "/" + auxiliary.MappingPeopletoFolder(Indivs[index]) + "/" + file_name
			f, _ := os.Create(file_path)
			w := csv.NewWriter(f)

			w.WriteAll(string_data)
			w.Flush()
			f.Close()

			<-ch
			wg.Done()
		}()

	}

	wg.Wait()

	fmt.Printf("BlockSize: "+strconv.Itoa(batch_size)+", Finish Data Encryption and Save of "+strconv.Itoa(len(Indivs))+" Individuals in (%s)\n", time.Since(now))

}

// Read a ciphertext segment
func ReadSegmentData(people auxiliary.People, segID int, batch_size int, option bool) (Variants []Variant, keyhash1, keyhash2 []byte) {
	subfolder := "BlockSize_" + strconv.Itoa(batch_size)
	file_name := people.Name
	if option {
		file_name = file_name + "_Hosted"
	}
	file_name = file_name + "_Segments.csv"
	file_path := "../../../Segments_Enc_Data_Trivium/" + subfolder + "/" + auxiliary.MappingPeopletoFolder(people) + "/" + file_name
	path, _ := filepath.Abs(file_path)
	file, _ := os.Open(path)
	defer file.Close()
	r := csv.NewReader(file)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}

		if row[0] == people.Name {
			k1 := strings.Split(row[1], ":")[1][1:]
			kval1, _ := big.NewInt(1).SetString(k1, 0)
			keyhash1 = kval1.Bytes()
			k2 := strings.Split(row[2], ":")[1][1:]
			kval2, _ := big.NewInt(1).SetString(k2, 0)
			keyhash2 = kval2.Bytes()
			continue
		}

		if len(row[0]) < 8 {
			fmt.Println(row)
			fmt.Println(people)
		}

		if row[0][0:7] != "Segment" || row[0][7:] != strconv.Itoa(segID) {
			continue
		}

		seg_len, error := strconv.Atoi(row[1][17:])
		if error != nil {
			fmt.Println("Error:", error)
			return
		}

		row, err = r.Read()
		if err == io.EOF {
			break
		}

		Variants = make([]Variant, seg_len)

		for i := 0; i < seg_len; i++ {

			v := strings.Split(row[i], " ")
			Variants[i].Rsid = Encode_rsID(auxiliary.RsID_s2i(v[0]))
			Variants[i].Genotype = Encode_Genotype(auxiliary.Genotype_s2i(v[1]))
		}
		break

	}
	return
}

// Read the key hash
func ReadKeyhash(people auxiliary.People, batch_size int, option bool) (keyhash1, keyhash2 []byte) {
	subfolder := "BlockSize_" + strconv.Itoa(batch_size)
	file_name := people.Name
	if option {
		file_name = file_name + "_Hosted"
	}
	file_name = file_name + "_Segments.csv"
	file_path := "../../../Segments_Enc_Data_Trivium/" + subfolder + "/" + auxiliary.MappingPeopletoFolder(people) + "/" + file_name
	path, _ := filepath.Abs(file_path)
	file, _ := os.Open(path)
	defer file.Close()
	r := csv.NewReader(file)
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}

		if row[0] == people.Name {
			k1 := strings.Split(row[1], ":")[1][1:]
			kval1, _ := big.NewInt(1).SetString(k1, 0)
			keyhash1 = kval1.Bytes()
			k2 := strings.Split(row[2], ":")[1][1:]
			kval2, _ := big.NewInt(1).SetString(k2, 0)
			keyhash2 = kval2.Bytes()
			break
		}

	}
	return
}

// Generate and Save tfheb key
func GenAndSaveKey(params tfhe.Parameters[uint32]) {
	enc := tfhe.NewBinaryEncryptor(params)
	pk := auxiliary.GenLWEPublicKey_tfheb(enc)
	Save_SK(enc)
	Save_PK(pk)
}

// Read tfheb Secret Key
func ReadSK(enc *tfhe.BinaryEncryptor) {
	var buf bytes.Buffer
	file, _ := os.ReadFile("../../../Key_Information/Trivium_SecretKey")
	buf.Write(file)
	enc.BaseEncryptor.SecretKey.ReadFrom(&buf)
	// row_path := "../../../Key_Information/Trivium_SecretKey.csv"
	// path, _ := filepath.Abs(row_path)
	// file, _ := os.Open(path)
	// defer file.Close()
	// r := csv.NewReader(file)

	// sk_size := len(enc.BaseEncryptor.SecretKey.LWELargeKey.Value)

	// for {
	// 	row, err := r.Read()
	// 	if err != nil && err != io.EOF {
	// 		log.Fatalf("can not read, err is %+v", err)
	// 	}
	// 	if err == io.EOF {
	// 		break
	// 	}

	// 	for i := 0; i < sk_size; i++ {
	// 		val, _ := big.NewInt(1).SetString(row[i], 10)
	// 		enc.BaseEncryptor.SecretKey.LWELargeKey.Value[i] = uint32(val.Uint64())
	// 	}

	// }
	// for i := 0; i < enc.Parameters.GLWEDimension(); i++ {
	// 	enc.BaseEncryptor.FourierEvaluator.ToFourierPolyAssign(enc.BaseEncryptor.SecretKey.GLWEKey.Value[i], enc.BaseEncryptor.SecretKey.FourierGLWEKey.Value[i])
	// }
}

// Read tfheb Public Key
func ReadPK(params tfhe.Parameters[uint32]) (pk auxiliary.PublicKey_tfheb) {
	pk.Params = params
	row_path := "../../../Key_Information/Trivium_PublicKey.csv"
	path, _ := filepath.Abs(row_path)
	file, _ := os.Open(path)
	defer file.Close()

	r := csv.NewReader(file)

	sk_size := params.LWEDimension()

	count := 0
	pk.A = make([][]uint32, sk_size)

	for {
		row, err := r.Read()
		if err != nil && err != io.EOF {
			log.Fatalf("can not read, err is %+v", err)
		}
		if err == io.EOF {
			break
		}

		if count == sk_size {
			pk.B = make([]uint32, sk_size)
			for i := 0; i < sk_size; i++ {
				val, _ := big.NewInt(1).SetString(row[i], 10)
				pk.B[i] = uint32(val.Uint64())
			}
		} else {
			pk.A[count] = make([]uint32, sk_size)
			for i := 0; i < sk_size; i++ {
				val, _ := big.NewInt(1).SetString(row[i], 10)
				pk.A[count][i] = uint32(val.Uint64())
			}
		}

		count++

	}

	return
}

// Get Ciphertext SegKey with Public Key
func GetSegKeyFromPK(pk auxiliary.PublicKey_tfheb, rsid int, batch_size int, Indiv []auxiliary.People, option bool) (res1, res2 [][]tfhe.LWECiphertext[uint32]) {
	Data_Len := len(Indiv)
	res1 = make([][]tfhe.LWECiphertext[uint32], Data_Len)
	res2 = make([][]tfhe.LWECiphertext[uint32], Data_Len)

	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(Data_Len)
	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			seg_ID := auxiliary.SegmentID(Indiv[index], rsid, auxiliary.Seg_num)
			keyinfo1, _ := GenerateRawKey(Indiv[index], 1)
			keyinfo2, _ := GenerateRawKey(Indiv[index], 2)

			var segkey1, segkey2 []int
			if option {
				segkey1 = GenKeyHostedMode(keyinfo1, batch_size)
				segkey2 = GenKeyHostedMode(keyinfo2, batch_size)
			} else {
				segkey1 = GenSegmentKey(keyinfo1, seg_ID, batch_size)
				segkey2 = GenSegmentKey(keyinfo2, seg_ID, batch_size)
			}

			res1[index] = make([]tfhe.LWECiphertext[uint32], 80)
			res2[index] = make([]tfhe.LWECiphertext[uint32], 80)

			for j := 0; j < 80; j++ {
				res1[index][j] = auxiliary.EncWithPublicKey_tfheb(uint32(segkey1[j]), pk)
				res2[index][j] = auxiliary.EncWithPublicKey_tfheb(uint32(segkey2[j]), pk)
			}

			<-ch
			wg.Done()
		}()

	}

	wg.Wait()

	fmt.Printf("BlockSize: "+strconv.Itoa(batch_size)+", Finish Key Encryption of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))

	return
}

// Get Ciphertext SegKey with Public Key, option decide whehter Hosted Mode,then appid is useless
func GetSegKeyFromPKForAppID(pk auxiliary.PublicKey_tfheb, appid int, batch_size int, Indiv []auxiliary.People, option bool) (res1, res2 [][]tfhe.LWECiphertext[uint32]) {
	Data_Len := len(Indiv)

	res1 = make([][]tfhe.LWECiphertext[uint32], Data_Len)
	res2 = make([][]tfhe.LWECiphertext[uint32], Data_Len)

	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(Data_Len)
	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			keyinfo1, _ := GenerateRawKey(Indiv[index], 1)
			keyinfo2, _ := GenerateRawKey(Indiv[index], 2)
			var segkey1, segkey2 []int
			if option {
				segkey1 = GenKeyHostedMode(keyinfo1, batch_size)
				segkey2 = GenKeyHostedMode(keyinfo2, batch_size)
			} else {
				segkey1 = GenSegmentKey(keyinfo1, appid, batch_size)
				segkey2 = GenSegmentKey(keyinfo2, appid, batch_size)
			}
			res1[index] = make([]tfhe.LWECiphertext[uint32], 80)
			res2[index] = make([]tfhe.LWECiphertext[uint32], 80)

			for j := 0; j < 80; j++ {
				res1[index][j] = auxiliary.EncWithPublicKey_tfheb(uint32(segkey1[j]), pk)
				res2[index][j] = auxiliary.EncWithPublicKey_tfheb(uint32(segkey2[j]), pk)
			}

			<-ch
			wg.Done()
		}()

	}

	wg.Wait()

	fmt.Printf("BlockSize: "+strconv.Itoa(batch_size)+", Finish Key Encryption of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))

	return
}

// Get the Ciphertext Data Segment for Calculation
func GetCiphertextData(rsid int, eval *tfhe.BinaryEvaluator, batch_size int, Indiv []auxiliary.People, option bool) [][]Variant_TFHE {
	Data_Len := len(Indiv)

	now := time.Now()
	Data := make([][]Variant_TFHE, Data_Len)

	numCores := runtime.NumCPU()

	var wg sync.WaitGroup
	wg.Add(Data_Len)

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}

		go func() {
			seg_ID := auxiliary.SegmentID(Indiv[index], rsid, auxiliary.Seg_num)
			Seg, _, _ := ReadSegmentData(Indiv[index], seg_ID, batch_size, option)
			Data[index] = make([]Variant_TFHE, len(Seg))
			for j := 0; j < len(Seg); j++ {
				Data[index][j] = Enc_Variant_Raw(Seg[j], eval.Parameters)
			}

			<-ch
			wg.Done()
		}()

	}

	wg.Wait()
	fmt.Printf("BlockSize: "+strconv.Itoa(batch_size)+", Get Ciphertext Data in (%s)\n", time.Since(now))
	return Data
}

// Recover the data for calculation in ciphertext
func Data_Recover(eval *tfhe.BinaryEvaluator, Data [][]Variant_TFHE, segkey1 [][]tfhe.LWECiphertext[uint32], segkey2 [][]tfhe.LWECiphertext[uint32], Indiv []auxiliary.People, rsid int, option bool) [][]Variant_TFHE {
	Data_Len := len(Data)
	now := time.Now()

	Dec_Data := make([][]Variant_TFHE, Data_Len)

	var wg sync.WaitGroup
	wg.Add(Data_Len)
	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			iv := make([]int, 80)
			if option {
				iv = GenIVHostedMode(auxiliary.SegmentID(Indiv[index], rsid, auxiliary.Seg_num))
			}
			var triv Trivium_TFHE
			triv.Init(segkey1[index], segkey2[index], eval.ShallowCopy(), iv)

			Dec_Data[index] = DecCiphertextBySegKey(Data[index], &triv, eval.ShallowCopy())
			<-ch
			wg.Done()
		}()

	}

	wg.Wait()

	fmt.Printf("Finish Data Recover of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))
	return Dec_Data
}

// Get How many 0|0, 0|1, 1|1 over a population
func GetDistribute(rsid int, eval *tfhe.BinaryEvaluator, Dec_Data [][]Variant_TFHE) []BigValueCiphertext {
	Data_Len := len(Dec_Data)
	var QueryVariant Variant
	QueryVariant.Rsid = Encode_rsID(rsid)
	QueryVariant_TFHE := Enc_Variant_Raw(QueryVariant, eval.Parameters)

	QueryResult := make([][]BigValueCiphertext, 3)
	for i := 0; i < 3; i++ {
		QueryResult[i] = make([]BigValueCiphertext, Data_Len)
		for j := 0; j < Data_Len; j++ {
			QueryResult[i][j] = NewBigValueCiphertext(eval.Parameters)
		}
	}

	q := make([]BigValueCiphertext, 3)
	for i := 0; i < 3; i++ {
		q[i] = NewBigValueCiphertext(eval.Parameters)
	}

	now := time.Now()

	var wg sync.WaitGroup
	wg.Add(Data_Len)
	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			new_eval := eval.ShallowCopy()

			for j := 0; j < len(Dec_Data[index]); j++ {
				qr := GenotypeFromTwoVariants(Dec_Data[index][j], QueryVariant_TFHE, new_eval)
				for k := 1; k < 3; k++ {
					QueryResult[k][index].Values[0] = new_eval.OR(QueryResult[k][index].Values[0], qr[k])
				}
				QueryResult[0][index].Values[0] = new_eval.OR(QueryResult[0][index].Values[0], qr[0])
			}
			QueryResult[0][index].Values[0] = new_eval.NOT(QueryResult[0][index].Values[0])

			<-ch
			wg.Done()
		}()
	}

	wg.Wait()

	for i := 0; i < Data_Len; i++ {
		for j := 0; j < 3; j++ {
			q[j] = AddBigValueCiphertext(q[j], QueryResult[j][i], eval)
		}
	}

	fmt.Printf("Finish Query of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))
	return q
}

// query a rsid in ciphertext
func QueryCiphertext(rsid int, segkey1, segkey2 [][]tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator, batch_size int, Indiv []auxiliary.People, option bool) []BigValueCiphertext {

	Data_Len := len(Indiv)

	fmt.Println("BlockSize: " + strconv.Itoa(batch_size) + ", Processing Query of " + strconv.Itoa(Data_Len) + " individuals...")

	Data := GetCiphertextData(rsid, eval, batch_size, Indiv, option)

	Dec_Data := Data_Recover(eval, Data, segkey1, segkey2, Indiv, rsid, option)

	res := GetDistribute(rsid, eval, Dec_Data)

	return res

}

// Get Ciphertext CODIS Data
func GetCodisDataCiphtertext(eval *tfhe.BinaryEvaluator, Data_Len int, batch_size int, option bool) []CODIS_TFHE {
	now := time.Now()
	rawdata, _, _ := ReadCODISData(batch_size, option)
	triv_rawdata := Encode_CODIS(rawdata)
	Data := make([]CODIS_TFHE, Data_Len)

	numCores := runtime.NumCPU()

	var wg sync.WaitGroup
	wg.Add(Data_Len)

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}

		go func() {
			Data[index] = Enc_CODIS_Raw(triv_rawdata[index], eval.Parameters)

			<-ch
			wg.Done()
		}()

	}

	wg.Wait()
	fmt.Printf("BlockSize: "+strconv.Itoa(batch_size)+", Get Ciphertext Data in (%s)\n", time.Since(now))
	return Data
}

// Data Recover for CODIS Data
func Data_Recover_CODIS(eval *tfhe.BinaryEvaluator, Data_Len int, Data []CODIS_TFHE, segkey1 [][]tfhe.LWECiphertext[uint32], segkey2 [][]tfhe.LWECiphertext[uint32], option bool) []CODIS_TFHE {
	now := time.Now()

	Dec_Data := make([]CODIS_TFHE, Data_Len)

	var wg sync.WaitGroup
	wg.Add(Data_Len)

	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			iv := make([]int, 80)
			if option {
				iv = GenIVHostedMode(applications.App_id_SearchPerson)
			}

			var triv Trivium_TFHE
			triv.Init(segkey1[index], segkey2[index], eval.ShallowCopy(), iv)

			Dec_Data[index] = DecCODISCiphertextBySegKey(Data[index], &triv, eval.ShallowCopy())
			<-ch
			wg.Done()
		}()

	}

	wg.Wait()

	fmt.Printf("Finish Data Recover of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))
	return Dec_Data
}

// Compare the data with target CODIS to find the target person
func CODIS_Set_Comparasion(Data_Len int, Dec_Data []CODIS_TFHE, eval *tfhe.BinaryEvaluator, QueryCODIS CODIS_TFHE) []tfhe.LWECiphertext[uint32] {
	now := time.Now()

	res := make([]tfhe.LWECiphertext[uint32], Data_Len)

	var wg sync.WaitGroup
	wg.Add(Data_Len)

	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		ch <- struct{}{}
		go func() {
			res[index] = Compare_CODIS_TFHE(QueryCODIS, Dec_Data[index], eval.ShallowCopy())
			<-ch
			wg.Done()
		}()
	}

	wg.Wait()

	fmt.Printf("Finish Comparison of "+strconv.Itoa(Data_Len)+" Individuals in (%s)\n", time.Since(now))
	return res
}

// query a person in ciphertext
func SearchPerson(QueryCODIS CODIS_TFHE, segkey1, segkey2 [][]tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator, Data_Len int, batch_size int, option bool) (res []tfhe.LWECiphertext[uint32]) {

	fmt.Println("BlockSize: " + strconv.Itoa(batch_size) + ", Processing Person Searching in " + strconv.Itoa(Data_Len) + " individuals...")
	Data := GetCodisDataCiphtertext(eval, Data_Len, batch_size, option)

	Dec_Data := Data_Recover_CODIS(eval, Data_Len, Data, segkey1, segkey2, option)

	res = CODIS_Set_Comparasion(Data_Len, Dec_Data, eval, QueryCODIS)

	return

}

// A user can query his rsid
func Userquery(people auxiliary.People, rsid int, segkey1, segkey2 []tfhe.LWECiphertext[uint32], batch_size int, eval *tfhe.BinaryEvaluator, option bool) (res [4]tfhe.LWECiphertext[uint32]) {

	seg_ID := auxiliary.SegmentID(people, rsid, auxiliary.Seg_num)
	Seg, _, _ := ReadSegmentData(people, seg_ID, batch_size, option)

	var QueryVariant Variant
	QueryVariant.Rsid = Encode_rsID(rsid)
	QueryVariant_TFHE := Enc_Variant_Raw(QueryVariant, eval.Parameters)

	Data_ct := make([]Variant_TFHE, len(Seg))
	for j := 0; j < len(Seg); j++ {
		Data_ct[j] = Enc_Variant_Raw(Seg[j], eval.Parameters)
	}

	now := time.Now()

	iv := make([]int, 80)
	if option {
		iv = GenIVHostedMode(seg_ID)
	}
	var triv Trivium_TFHE
	triv.Init(segkey1, segkey2, eval, iv)

	Dec_ct := DecCiphertextBySegKey(Data_ct, &triv, eval)

	res = Compare_RSID_TFHE(Dec_ct[0], QueryVariant_TFHE, eval)

	for i := 1; i < len(Dec_ct); i++ {
		c := Compare_RSID_TFHE(Dec_ct[i], QueryVariant_TFHE, eval)
		for j := 0; j < 4; j++ {
			res[j] = eval.OR(res[j], c[j])
		}
	}

	fmt.Printf("Finish UserQuery in (%s)\n", time.Since(now))

	return

}

// Get genotype => BigvalueCiphertext, not consideration the situation of 0|2 or larger
func GetMergedGenotype(rsid int, eval *tfhe.BinaryEvaluator, Dec_Data [][]Variant_TFHE) []BigValueCiphertext {
	Data_Len := len(Dec_Data)
	var QueryVariant Variant
	QueryVariant.Rsid = Encode_rsID(rsid)
	QueryVariant_TFHE := Enc_Variant_Raw(QueryVariant, eval.Parameters)

	res := make([]BigValueCiphertext, Data_Len)
	for i := 0; i < Data_Len; i++ {
		res[i] = NewBigValueCiphertext(eval.Parameters)
	}

	var wg sync.WaitGroup
	wg.Add(Data_Len)
	numCores := runtime.NumCPU()

	ch := make(chan struct{}, numCores/2)

	for i := 0; i < Data_Len; i++ {
		index := i
		new_eval := eval.ShallowCopy()
		ch <- struct{}{}
		go func() {

			for j := 0; j < len(Dec_Data[index]); j++ {
				gt := Compare_RSID_TFHE(Dec_Data[index][j], QueryVariant_TFHE, new_eval)
				temp1 := NewBigValueCiphertext(new_eval.Parameters)
				temp2 := NewBigValueCiphertext(new_eval.Parameters)
				temp1.Values[0] = gt[0]
				temp2.Values[0] = gt[2]
				res[index] = AddBigValueCiphertext(res[index], temp1, new_eval)
				res[index] = AddBigValueCiphertext(res[index], temp2, new_eval)
				res[index].UpperBound = 2
			}

			<-ch
			wg.Done()
		}()
	}

	wg.Wait()

	return res
}

// Perform a Boolean GWAS in ciphertext
func GWASBool(rsid int, segkey1, segkey2 [][]tfhe.LWECiphertext[uint32], eval *tfhe.BinaryEvaluator, batch_size int, Indiv []auxiliary.People, phenotype []BigValueCiphertext, option bool) (Fix16, Int72Ciphertext) {

	Data_Len := len(Indiv)

	fmt.Println("BlockSize: " + strconv.Itoa(batch_size) + ", Processing GWAS of " + strconv.Itoa(Data_Len) + " individuals...")

	Data := GetCiphertextData(rsid, eval, batch_size, Indiv, option)

	Dec_Data := Data_Recover(eval, Data, segkey1, segkey2, Indiv, rsid, option)

	now := time.Now()

	genotype := GetMergedGenotype(rsid, eval, Dec_Data)

	bit_res, exp_res := GWASWithPValue_Ciphertext(genotype, phenotype, Data_Len, eval)

	fmt.Printf("Finish GWAS in (%s)\n", time.Since(now))

	return bit_res, exp_res

}
