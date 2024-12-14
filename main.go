package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	inputFile := "mnemonics.txt"
	outputFile := "pks.txt"

	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file", err)
	}
	defer file.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("failed to creat file", err)
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(file)
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	for scanner.Scan() {
		mnemonic := strings.TrimSpace(scanner.Text())
		if mnemonic == "" {
			continue
		}

		if !bip39.IsMnemonicValid(mnemonic) {
			log.Printf("Invalid mnemonic ", mnemonic)
			continue
		}

		seed := bip39.NewSeed(mnemonic, "")

		masterKey, err := bip32.NewMasterKey(seed)
		if err != nil {
			log.Printf("Failed to generate master key for mnemonic%s,err:%v ", mnemonic, err)
			continue
		}

		purposeKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
		if err != nil {
			log.Printf("failed to Derive purpose key for mnemonic%s,%v", mnemonic, err)
			continue
		}

		coinTypeKey, err := purposeKey.NewChildKey(bip32.FirstHardenedChild + 60)
		if err != nil {
			log.Printf("failed to Derive cointype key for mnemonic%s,%v", mnemonic, err)
			continue
		}
		accountKey, err := coinTypeKey.NewChildKey(bip32.FirstHardenedChild + 0)
		if err != nil {
			log.Printf("failed to Derive account key for mnemonic%s,%v", mnemonic, err)
		}
		changeKey, err := accountKey.NewChildKey(0)
		if err != nil {
			log.Printf("failed to Derive purpose key for mnemonic%s,%v", mnemonic, err)
			continue
		}
		addressKey, err := changeKey.NewChildKey(0)
		if err != nil {
			log.Printf("failed to Derive purpose key for mnemonic%s,%v", mnemonic, err)
			continue
		}
		pk := fmt.Sprintf("%x\n", addressKey.Key)
		if _, err := writer.WriteString(pk); err != nil {
			log.Printf("failed to Derive purpose key for mnemonic%s,%v", mnemonic, err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading input file:%v", err)
	}
	fmt.Println("Successfully generated private keys for all mnemonics in the input file. Output saved to", outputFile)
}
