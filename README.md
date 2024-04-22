<div align="center">
    <img src="docs/images/logo.png" width = "210" height = "190" alt="Governome_logo">
</div>

# Governome - Governome: An owner-governed genomic data management framework based on blockchain


## Introduction

Governome is the first owner-governed genomic data management framework, which can assist Data Owners in maintaining absolute control over their genomics data, including the final decision-making authority and the right to be informed.

This repository showcases the available applications of the current version of Governome, including data preprocessing for whole-genome data, population single variant queries, GWAS analysis, and a functional batch for identifying target individuals. Additionally, this repository demonstrates how Key Custodians upload information and provide proofs to participate in the workflow of Governome. All the homomorphical computation modules in Governome are based on the excellent library [tfhe-go](https://github.com/sp301415/tfhe-go), and all the zk-SNARKs modules in Governome are based on [gnark](https://github.com/Consensys/gnark/tree/master).

## Installation

### Install go 1.21

#### 1. Download the latest Golang version 1.21 by visiting the official website (https://golang.org/dl/) and copying the download link for the Linux tarball. An example is shown below:

```
wget https://golang.org/dl/go1.21.6.linux-amd64.tar.gz
```

#### 2. Extract the downloaded tarball to your preferred local directory. In this example, we'll use `$HOME/.local`:

```
tar -xvzf go1.21.6.linux-amd64.tar.gz -C $HOME/.local
```

#### 3. Remove the tarball after extraction:

```
rm go1.18.linux-amd64.tar.gz
```

#### 4. Set up your Go workspace and environment variables:

##### a. Create the required directory structure:

```
mkdir -p $HOME/go/{bin,src,pkg}
```

##### b. Open your `~/.bashrc` or `~/.profile` file with a text editor, such as vim:

```
vim ~/.bashrc
```

##### c. Add the following lines to the end of the file:

```
export GOPATH=$HOME/go
export GOROOT=$HOME/.local/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

##### d. Save the file and exit the text editor.

##### e. Apply the changes to your current session:

```
source ~/.bashrc
```

#### 5. Verify the installation:

```
go version
```

### Clone this repo

You can clone this repo as following:

```
git clone git@github.com:HKU-BAL/Governome.git
```

We advise to organize the data in the following way to ensure the efficiency of accessing and processing data:

```
${PATH}
└── Governome_RootFolder/
    ├── Governome/
    ├── Plaintext_Data/
    ├── Individuals/
    ├── Phenotype/
    └── ...
```

## Data Preprocessing

In Governome, we process whole-genome data based on VCF (Variant Call Format) files. Specifically, considering that the original VCF files can be overly cumbersome, we provide a simplified version that only retains the rsID and genotype columns. You can download this simplified data here. If you find the whole-genome data to be too large, you can download a simplified version based on `chromosome 20` from here. Please note that, at this moment, modify the `Seg_num` in `./auxiliary/params.go` to `2048`.

In Governome, data is stored in encrypted form. To encrypt the raw data, you need to run the following command:

```
cd ./examples/data_process/
go run main.go -Segment
```

Since the `1000 Genomes dataset` does not provide short tandem repeat loci, we have chosen to randomly generate this data for the `2504` individuals and encrypt it. Here is an example code:

```
go run main.go -Codis -CodisEnc
```

For the sake of demonstration, we have omitted the process of collaboratively generating the public key and evaluation key in ThFHE. You can generate the public and private key pair for TFHE first to facilitate subsequent computations:

```
go run main.go -GenKey
```

If necessary, you can modify the `-BlockSize` parameter to select a larger block setting. Considering the memory limitations of the user, the `-BlockSize` for the stream cipher key is set to `1` by default. Additionally, you can modify the `Seg_num` in `./auxiliary/params.go` to set a different number of segments.

## Quick Start

### Upload a SegKey and generating a proof

This module demonstrates how, as a Key Custodian, you will generate the ciphertext and zero-knowledge proofs that need to be submitted for a transaction. Please ensure that you have executed the corresponding command for generating the public and private key pair for TFHE.

#### a. If you are interested in observing how zero-knowledge proofs are generated, please execute the following command:

```
cd ../user_proof
go run main.go -Rsid ${Your Target rsID} -Username ${DataOwner Name, e.g. HG00096} -ID ${key custodian ID, 1 or 2 here}
```

#### b. If you want to generate all proofs and ciphertexts for a rsid, you can execute the following command:

```
go run main.go -All -Rsid ${Your Target rsID} 
```

#### c. If you want to generate all proofs and ciphertexts for an appID, you can execute the following command:

```
go run main.go -All -APPID ${Your Target appID} 
```

Noted that b and c are prepared for subsequent demonstrations, which take time. If you simply want to experience the full functionality of Governome, please ignore them.

### User query

As a Data Owner, you are highly interested in your own genotype data. To fulfill this, you can initiate a query to Governome to gain insights into your health condition. Governome provides a module specifically designed for this purpose. You can use the following command to perform the query:

```
cd ../data_owner_query/
go run main.go -Rsid ${Your Target rsID} -Username ${DataOwner Name, e.g. HG00096}
```

For the sake of demonstration, the parameters used here are highly insecure. If you wish to use secure parameters, please add the statement `-Toy=false`. If you have executed [b](https://github.com/HKU-BAL/Governome/blob/main/README.md#b-if-you-want-to-generate-all-proofs-and-ciphertexts-for-a-rsid-you-can-execute-the-following-command), you may also choose to add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Single SNP Query

As the head of a pharmaceutical company, you and your team intend to develop a new drug based on a specific target SNP. However, you are uncertain about the true correlation between the target and the disease. In this regard, you can initiate a distribution query to Governome regarding this target. The command is as follows:

```
cd ../querySingleSnp/
go run main.go -Rsid ${Your Target rsID}
```

And you will obtain the result you are interested in. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Single SNP GWAS

After obtaining the distribution of Single SNPs, you are not satisfied with simple statistical results and wish to conduct further refined analysis. You want to select a population and perform GWAS analysis on the target population to determine associations using p-values. Governome provides a module for this purpose, and you can execute the following command:

```
cd ../gwas/
go run main.go -Rsid ${Your Target rsID} -Population ${Your interested population, e.g. EUR}
```

Noted that the the Phenotype comes from Hail, you can download it here. The default Phenotype is PurpleHair. If you want to change it, you can modify the Phenotype file by yourself. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Search Person

As a law enforcement agency, you have encountered individuals with unidentified identities in your jurisdiction. To determine their identities, you can use Governome's functional batch to confirm their identities. Here, the individual's identity is no longer represented by strings like "HG00096" but is standardized as integers from 0 to 2503. You can run the following command:

```
cd ../search_person/
go run -GroundTruth ${Your Target Person's ID, 0 ~ 2503}
```

Here, you can use -GroundTruth to set the individuals of interest. If you do not wish to perform the query on individuals from the 1000 Genomes dataset, you can set it to `-1`, and we will randomly generate such individuals for you. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file if you have executed [c](https://github.com/HKU-BAL/Governome/blob/main/README.md#c-if-you-want-to-generate-all-proofs-and-ciphertexts-for-an-appid-you-can-execute-the-following-command).


## Usage

### Data Preprocessing

### Upload a SegKey and generating a proof

### User query

### Single SNP Query

### Single SNP GWAS

### Search Person

