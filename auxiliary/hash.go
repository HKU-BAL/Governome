package auxiliary

import (
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"golang.org/x/crypto/sha3"
)

// Extend a byte slice to asked length
func PadBytes(b []byte, desiredLength int) []byte {
	if len(b) < desiredLength {
		paddedBytes := make([]byte, desiredLength-len(b))
		paddedBytes = append(paddedBytes, b...)
		return paddedBytes
	}
	return b
}

// Convert any Int or Uint type to big.Int
func ConvertToBigInt(data interface{}) (*big.Int, error) {
	value := reflect.ValueOf(data)

	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return big.NewInt(value.Int()), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return big.NewInt(0).SetUint64(value.Uint()), nil
	case reflect.String:
		bigInt := new(big.Int)
		_, success := bigInt.SetString(value.String(), 0)
		if !success {
			return nil, fmt.Errorf("failed to convert string to *big.Int")
		}
		return bigInt, nil
	default:
		return nil, fmt.Errorf("unsupported type: %s", value.Type())
	}
}

// Transfer a slice to []byte
func ConvertToBigIntByteSlice(data interface{}, curveID ecc.ID, MimcHashCurve hash.Hash) ([]byte, error) {
	value := reflect.ValueOf(data)

	if value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		length := value.Len()
		result := make([]byte, 0)

		for i := 0; i < length; i++ {
			element := value.Index(i)

			var temp *big.Int
			var err error

			switch element.Type().Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				temp, err = ConvertToBigInt(element.Int())
				if err != nil {
					fmt.Println("Error:", err)
					return nil, err
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				temp, err = ConvertToBigInt(element.Uint())
				if err != nil {
					fmt.Println("Error:", err)
					return nil, err
				}
			case reflect.String:
				temp, err = ConvertToBigInt(element.String())
				if err != nil {
					fmt.Println("Error:", err)
					return nil, err
				}
			default:
				return nil, fmt.Errorf("cannot convert element at index %d to *big.Int", i)
			}
			temp = temp.Mod(temp, curveID.BaseField())
			result = append(result, PadBytes(temp.Bytes(), MimcHashCurve.Size())...)
		}

		return result, nil
	}

	return nil, fmt.Errorf("input data is not a slice or array")
}

// General MimcHash function, int and uint takes value, others take bytes, limited in fr
func MimcHash(slice interface{}, curveID ecc.ID, MimcHashCurve hash.Hash) ([]byte, error) {
	goMimc := MimcHashCurve.New()
	sliceValue := reflect.ValueOf(slice)
	if sliceValue.Kind() != reflect.Slice {
		return nil, fmt.Errorf("input is not a slice")
	}

	for i := 0; i < sliceValue.Len(); i++ {
		element := sliceValue.Index(i)
		var bytes []byte
		switch element.Kind() {
		case reflect.String:
			bytes = []byte(element.String())
			temp := big.NewInt(1).SetBytes(bytes)
			temp = temp.Mod(temp, curveID.BaseField())
			bytes = temp.Bytes()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
			reflect.Uint64:
			temp, err := ConvertToBigInt(element.Uint())
			if err != nil {
				fmt.Println("Error:", err)
				return nil, err
			}
			bytes = temp.Bytes()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
			reflect.Int64:
			temp, err := ConvertToBigInt(element.Int())
			if err != nil {
				fmt.Println("Error:", err)
				return nil, err
			}
			bytes = temp.Bytes()
		case reflect.Float32, reflect.Float64:
			bytes = []byte(fmt.Sprintf("%f", element.Float()))
		case reflect.Bool:
			bytes = []byte(fmt.Sprintf("%t", element.Bool()))
		case reflect.Complex64, reflect.Complex128:
			bytes = []byte(fmt.Sprintf("%v", element.Complex()))
		default:
			return nil, fmt.Errorf("unsupported element type: %v", element.Kind())
		}

		length := ((len(bytes)-1)/MimcHashCurve.Size() + 1) * MimcHashCurve.Size()
		bytes = PadBytes(bytes, length)

		_, err := goMimc.Write(bytes)
		if err != nil {
			fmt.Println("Error:", err)
			return nil, err
		}

	}

	hashValue := goMimc.Sum(nil)

	return hashValue, nil
}

// Raw MimcHash function, input bytes and output bytes, limited in fr
func MimcHashRaw(bytes []byte, MimcHashCurve hash.Hash) ([]byte, error) {
	goMimc := MimcHashCurve.New()
	goMimc.Reset()
	length := ((len(bytes)-1)/MimcHashCurve.Size() + 1) * MimcHashCurve.Size()
	bytes = PadBytes(bytes, length)
	_, err := goMimc.Write(bytes)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}
	hashValue := goMimc.Sum(nil)
	return hashValue, err
}

// Mimc function used for slice like {"1", "2"}, take the value as input, limited in fr
func MimcHashString(str []string, curveID ecc.ID, MimcHashCurve hash.Hash) ([]byte, error) {
	bytes, err := ConvertToBigIntByteSlice(str, curveID, MimcHashCurve)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, err
	}
	return MimcHashRaw(bytes, MimcHashCurve)
}

// Mimc function for big.Int, limited in fr
func MimcHashBigValue(bigvalue []*big.Int, curveID ecc.ID, MimcHashCurve hash.Hash) ([]byte, error) {
	str := make([]string, len(bigvalue))
	for i := 0; i < len(str); i++ {
		str[i] = bigvalue[i].String()
	}
	return MimcHashString(str, curveID, MimcHashCurve)
}

// Take string as input and output its sha3 hash value
func GenSHA3FromString(s string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(s))
	hashval_bytes := h.Sum(nil)
	return hashval_bytes
}

// Judge the ID of a segment of an individual from the input rsID
func SegmentID(nickname string, rsid int, modulus int) int {
	if modulus <= 1 {
		log.Fatalf("Invalid modulus!")
	}
	fullinfo := nickname + strconv.Itoa(rsid)
	hashval_bytes := GenSHA3FromString(fullinfo)
	hash_val := new(big.Int).SetBytes(hashval_bytes)
	hash_mod := hash_val.Mod(hash_val, big.NewInt(int64(modulus)))
	return int(hash_mod.Int64())
}
