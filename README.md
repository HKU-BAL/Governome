<div align="center">
    <img src="docs/images/logo.png" width = "210" height = "190" alt="Governome_logo">
</div>

# Governome - Towards a new standard in genomic data privacy: a realization of owner-governance

Contact: Ruibang Luo, Jingcheng Zhang  
Email: rbluo@cs.hku.hk, zhangjc@connect.hku.hk  

----

## Introduction

Governome is an owner-governed genomic data management system based on blockchain, it designed to empower individuals with absolute control over their genomic data during data sharing.

This repository showcases the available applications of the current version of Governome, including data preprocessing for whole-genome data, individual variant query, cohort study, GWAS analysis, and forensics. Additionally, this repository demonstrates how data owners and hospitals upload information and provide proofs to participate in the workflow of Governome. 

All the homomorphical computation modules in Governome are based on the excellent library [tfhe-go](https://github.com/sp301415/tfhe-go), and all the zk-SNARKs modules in Governome are based on [gnark](https://github.com/Consensys/gnark/tree/master).

----

## Contents

* [Introduction](#introduction)
* [Installation](#installation)
  * [Install go 1.21](#1-install-go-121)
  * [Get Governome source code](#2-get-governome-source-code)
* [Data Preprocessing](#data-preprocessing)
* [Quick Start](#quick-start)
  * [Upload a SegKey and generating a proof](#upload-a-segkey-and-generating-a-proof)
  * [Individual variant query](#individual-variant-query)
  * [Cohort study](#cohort-study)
  * [Single SNP GWAS](#single-snp-gwas)
  * [Forensics](#forensics)
* [Usage](#usage)
  * [Data Preprocessing](#data-preprocessing-1)
  * [Upload a SegKey and generating a proof](#upload-a-segkey-and-generating-a-proof-1)
  * [Individual variant query](#individual-variant-query-1)
  * [Cohort study](#cohort-study-1)
  * [Single SNP GWAS](#single-snp-gwas-1)
  * [Forensics](forensics-1)

----

## Installation

### 1. Install go 1.21

Download and install Golang from the official website (https://golang.org/dl/).

```
# Download the latest Golang version 1.21 by visiting the official website (https://golang.org/dl/) and, 
# copying the download link for the Linux tarball.
# An example is shown below:
wget https://golang.org/dl/go1.21.10.linux-amd64.tar.gz

# Extract the downloaded tarball to your preferred local directory. In this example, we'll use `$HOME/.local`:
mkdir -p $HOME/.local
tar -xvzf go1.21.10.linux-amd64.tar.gz -C $HOME/.local

# Remove the tarball after extraction
rm go1.21.10.linux-amd64.tar.gz

# Set up your Go workspace and environment variables
## Create the required directory structure:
mkdir -p $HOME/go/{bin,src,pkg}

## add link to bashrc or .profile
## add the GOPATH,GOROOT to your `~/.bashrc` or `~/.profile`
echo 'export GOPATH=$HOME/go
export GOROOT=$HOME/.local/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

## Verify the installation
## You will get "go version go1.21.10 linux/amd64" if installed successfully
go version
```

### 2. Get Governome source code

You can clone this repo as following:

```
mkdir Governome_RootFolder
cd Governome_RootFolder
git clone git@github.com:HKU-BAL/Governome.git
cd Governome

# $Governome_DIR is path of Governome
Governome_DIR=$(pwd)
```

We advise to create a root folder and organize the data in the following way to ensure the efficiency of accessing and processing data:

```
Governome_RootFolder/
    ├── Plaintext_Data/
    ├── Individuals/
    ├── Phenotype/
    ├── Segments_Enc_Data/
    └── ...
```

Here you need to update the [defaultPath](https://github.com/HKU-BAL/Governome/blob/main/defaultPath) for the root folder.

## Data Preprocessing

In Governome, we process whole-genome data based on VCF (Variant Call Format) files. We have chosen `1000 Genomes dataset` for benchmarking, and you can download the individual list [here](http://www.bio8.cs.hku.hk/governome/Individuals/). Specifically, considering that the original VCF files can be overly cumbersome, we provide a simplified version that only retains the rsID and genotype columns. You can download this simplified data [here](http://www.bio8.cs.hku.hk/governome/Plaintext_Data/) or the preprocessed version [here](http://www.bio8.cs.hku.hk/governome/Segments_Enc_Data/). If you find the whole-genome data too large, you can download a simplified version based on `chromosome 20` from [here](http://www.bio8.cs.hku.hk/governome/chr20/Plaintext_Data/). Please note that, at this moment, modify the `Seg_num` in `./auxiliary/params.go` to `1024` or `2048`.

In Governome, data is stored in encrypted form. If you have already downloaded the preprocessed data, please ignore this step. To encrypt the raw data, you need to run the following command:

```
cd ${Governome_DIR}/examples/data_process/
go run main.go -Segment

# the raw data is available at ${Governome_RootFolder}/Segments_Enc_Data
```

Since the `1000 Genomes dataset` does not provide short tandem repeat loci, we have chosen to randomly generate this data for the `2504` individuals and encrypt it. Here is an example code:

```
cd ${Governome_DIR}/examples/data_process/
go run main.go -Codis -CodisEnc
```

For the sake of demonstration, we have omitted the process of collaboratively generating the public key and evaluation key in ThFHE. You can generate the public and private key pair for TFHE first to facilitate subsequent computations:

```
cd ${Governome_DIR}/examples/data_process/
go run main.go -GenKey
```

If you want to see how multi-parties collaboratively generating the public key and evaluation key in ThFHE, you can turn to [here](https://github.com/HKU-BAL/Governome/tree/main/ThFHE) for a Simple Demo.

## Quick Start

### Upload a SegKey and generating a proof

This module demonstrates how, as a data owner, you will generate the ciphertext and zero-knowledge proofs that need to be submitted for a query. Please ensure that you have executed the corresponding command for generating the public and private key pair for TFHE.

#### a. If you are interested in observing how zero-knowledge proofs are generated, please execute the following command:

```
cd ../user_proof
go run main.go -Rsid ${Your Target rsID} -User ${DataOwner Name, e.g. HG00096} -ID ${key custodian ID, 1 or 2 here}
```

#### b. If you want to generate all proofs and ciphertexts for a rsid, you can execute the following command:

```
go run main.go -All -Rsid ${Your Target rsID} 
```

#### c. If you want to generate all proofs and ciphertexts for an appID or a segID, you can execute the following command:

```
go run main.go -All -APPID ${Your Target appID} 
```

Noted that b and c are prepared for subsequent demonstrations, which take time. If you simply want to experience the full functionality of Governome, please ignore them.

### Individual variant query

As a Data Owner, you are highly interested in your own genotype data. To fulfill this, you can initiate a query to Governome to gain insights into your health condition. Governome provides a module specifically designed for this purpose. You can use the following command to perform the query:

```
cd ../data_owner_query/
go run main.go -Rsid ${Your Target rsID} -User ${DataOwner Name, e.g. HG00096}
```

For the sake of demonstration, the parameters used here are highly insecure. If you wish to use secure parameters, please add the statement `-Toy=false`. If you have executed [b](#b-if-you-want-to-generate-all-proofs-and-ciphertexts-for-a-rsid-you-can-execute-the-following-command), you may also choose to add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Cohort study

As the head of a pharmaceutical company, you and your team intend to develop a new drug based on a specific target SNP. However, you are uncertain about the true correlation between the target and the disease over a specific population. In this regard, you can initiate a distribution query to Governome regarding this target. The command is as follows:

```
cd ../querySingleSnp/
go run main.go -Rsid ${Your Target rsID} -Population ${Your interested population, e.g. EUR}
```

And you will obtain the result of how the distribution of different genotypes. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Single SNP GWAS

After obtaining the distribution of Single SNPs, you are not satisfied with simple statistical results and wish to conduct further refined analysis. You want to select a population and perform GWAS analysis on the target population to determine associations using p-values. Governome provides a module for this purpose, and you can execute the following command:

```
cd ../gwas/
go run main.go -Rsid ${Your Target rsID} -Population ${Your interested population, e.g. EUR}
```

Noted that the the Phenotype comes from Hail, you can download it [here](http://www.bio8.cs.hku.hk/governome/Phenotype/). The default Phenotype is CaffeineConsumption. If you want to change it, you can modify the Phenotype file by yourself. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file.

### Forensics

As authority/law enforcement agency, you have encountered individuals with unidentified identities in your jurisdiction. To determine their identities, you can use the 13 Short Tandem Repeat (D3S1358, vWA, FGA, D8S1179, D21S11, D18S51, D5S818, D13S317, D16S539, THO1, TPOX, CSF1PO, D7S820) in Governome's auxiliary data block to confirm their identities. Here, the individual's identity is no longer represented by strings like `HG00096` but is standardized as integers from `0` to `2503`. You can run the following command:

```
cd ../search_person/
go run main.go -GroundTruth ${Your Target Person's ID, 0 ~ 2503}
```

Here, you can use -GroundTruth to set the individuals of interest. If you do not wish to perform the query on individuals from the `1000 Genomes dataset`, you can set it to `-1`, and we will randomly generate such individuals for you. Similarly, you can set `-Toy=false` to use secure parameters, and add `-ReadKey` and `-Verify` to read and verify the proofs from a file if you have executed [c](#c-if-you-want-to-generate-all-proofs-and-ciphertexts-for-an-appid-or-a-segid-you-can-execute-the-following-command).


## Usage

### Data Preprocessing

#### Usage of ./example/data_process/main.go:

```
  -genkey
    	Whether to generate the keys
  -path string
    	Root FilePath (default "../../..")
  -precomputed
    	Whether owner choose to precompute the access token
  -seg
    	Whether to preprocess the data to segments
  -str
    	Whether to generate the str data
  -strenc
    	Whether to encrypt the str data
  -toy
    	Whether using Toy Parameters (default true)

```

### Upload a SegKey and generating a proof

#### Usage of ./example/user_proof/main.go:

```
  -all
    	Whether include all Individuals
  -begin int
    	Begin ID when generate all
  -end int
    	Begin ID when generate all (default 2504)
  -id int
    	1 or 2, 1 for owners, 2 for hospitals (default 1)
  -precomputed
    	Whether owner choose to precompute the access token
  -rsid string
    	Target Site in rsID (default "rs6053810")
  -segID int
    	AppID or SegID for all individual (default -1)
  -user string
    	User Name in 1kGP (default "HG00096")

```

### Individual variant query

#### Usage of ./example/data_owner_query/main.go:

```
  -precomputed
    	Whether owner choose to precompute the access token
  -read
    	Whether read Data from file, not suitable for toy params
  -rsid string
    	Target Site in rsID (default "rs6053810")
  -toy
    	Whether using Toy Parameters (default true)
  -user string
    	User Name in 1kGP (default "HG00096")
  -verify
    	Whether verifying the proofs

```

### Cohort study

#### Usage of ./example/querySingleSnp/main.go:

```
  -cohort string
    	Population, in 'AFR', 'AMR', 'EAS', 'EUR', 'SAS', 'ALL' (default "ALL")
  -precomputed
    	Whether owner choose to precompute the access token
  -read
    	Whether read Data from file, not suitable for toy params
  -rsid string
    	Target Site in rsID (default "rs6053810")
  -toy
    	Whether using Toy Parameters (default true)
  -verify
    	Whether verifying the proofs

```

### Single SNP GWAS

#### Usage of ./example/gwas/main.go:

```
  -cohort string
    	Population, in 'AFR', 'AMR', 'EAS', 'EUR', 'SAS' (default "EUR")
  -precomputed
    	Whether owner choose to precompute the access token
  -read
    	Whether read Data from file, not suitable for toy params
  -rsid string
    	Target Site in rsID (default "rs6053810")
  -toy
    	Whether using Toy Parameters (default true)
  -verify
    	Whether verifying the proofs

```

### Forensics

#### Usage of ./example/search_person/main.go:

```
  -groundtruth int
    	GroundTruthID in 1kGP
  -precomputed
    	Whether owner choose to precompute the access token
  -read
    	Whether read Data from file, not suitable for toy params
  -toy
    	Whether using Toy Parameters (default true)
  -verify
    	Whether verifying the proofs

```

