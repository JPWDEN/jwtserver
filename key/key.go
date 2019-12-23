package key

import (
	crypto "crypto/rand"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

const (
	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "~!@#$%^&*()-_=+<>,.?"
)

//Shannon Entropy, H, calculates the number of bits per symbol necesary to characterize
//a given random variable; in this case, the randomly generated key used to sign a JWT token
//          n
// H(X) =  ⎲ counti
//         ⎳ ------ * log2 (counti / n)
//         i=1   n
func calculateShannonEntropy(key string) float64 {
	if key == "" {
		return 0.0
	}
	N := float64(len(key))
	var count int
	var entropy float64
	fmt.Printf("Starting loop in calculateShannonEntropy for %s\n", key)
	for len(key) > 0 {
		key = strings.ReplaceAll(key, string(key[0]), "")
		if len(key) > 0 {
			count++
		}
	}
	for i := 1; i <= int(N); i++ {
		entropy += -float64(i) / float64(N) * math.Log2(float64(i)/N)
	}
	return entropy
}

//Calculation of the total nubmer of bits of entropy as a function of complexity compared to total character set.
func calculatePasswordEntropy(key string) float64 {
	R := 82.0 //Number of possible values.  Currently, all letters, digits, and symbols defined above
	return math.Log2(math.Pow(R, float64(len(key))))
}

func GenerateKey() []byte {
	rand.Seed(time.Now().UnixNano())
	var newKey []byte
	length := rand.Intn(5) + 15

	for i := 0; i < length; i++ {
		prob := rand.Float32() * float32(time.Now().UnixNano())
		switch {
		case prob < 0.5:
			newKey = append(newKey, letters[rand.Intn(len(letters)-1)])
		case prob >= 0.5 && prob < 0.75:
			newKey = append(newKey, digits[rand.Intn(len(digits)-1)])
		case prob >= 0.75:
			newKey = append(newKey, symbols[rand.Intn(len(symbols)-1)])
		}
	}
	shannonEntropy := calculateShannonEntropy(string(newKey))
	passwordEntropy := calculatePasswordEntropy(string(newKey))
	fmt.Printf("New KEY: %s with Shannon entropy and password entropy %f/%f\n", newKey, shannonEntropy, passwordEntropy)
	return newKey
}

func GenerateKeyCrypto() {
	length := rand.Intn(5) + 15
	newCryptoKey := make([]byte, length)
	_, err := crypto.Read(newCryptoKey[:])
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		panic(err)
	}
	fmt.Printf("STRING: %+v/%s\n", newCryptoKey, string(newCryptoKey))
	shannonEntropy := calculateShannonEntropy(string(newCryptoKey))
	passwordEntropy := calculatePasswordEntropy(string(newCryptoKey))
	fmt.Printf("New KEY: %s with Shannon entropy and password entropy %f/%f\n", newCryptoKey, shannonEntropy, passwordEntropy)
	return
}
