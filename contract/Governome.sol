// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

contract GenomeProcess{
    struct Genome_info{
        bool sharestate;
        uint256 datahash;
        uint256 medicalhash;
        uint256 hashkey1;
        uint256 hashkey2;
        address keyholder1;
        address keyholder2;
        address dataowner;
    }

    mapping(string => bool) public nicknameExistance;
    mapping(string => bool) public nicknameNeedShare;
    mapping(string => bool) public nicknameKey1NeedShare;
    mapping(string => bool) public nicknameKey2NeedShare;
    mapping(string => Genome_info) public nickname2genome;
    string[] public nicknameList;

    address QueryInitiator;
    address Hospital;
    address ComputingParty;
    address ContractCreator = 0x16A433305B92d33a6454767A93c38a11d6a46De1;

    bool public inited = false;
    

    bool public step1 = false;
    bool public step2 = false;
    bool public step3 = false;
    bool public step4 = false;
    bool public step5 = false;

    uint256 public IndivNum = 0;
    uint256 public IndivKey1Submitted = 0;
    uint256 public IndivKey2Submitted = 0;
    uint256 public ParticipantNum = 0;
    uint256 public ParticipantProvided = 0;

    string public rsid;

    event DataStored(string _nickname, uint256 _val);
    event StateChanged(string _nickname, bool _newstate);
    event QueryInited(string rsid, uint256 _ParticipantNumber);
    event IndivRecommend(string _nickname, uint256 _hash, uint256 _boxid);
    event Key1Submitted(uint256 _proofhash, uint256 _witnesshash, string _nickname);
    event Key2Submitted(uint256 _proofhash, uint256 _witnesshash, string _nickname);
    event ComputingFinished(uint256 _reshash);

    function BoxID(string memory _nickname) public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(_nickname, rsid))) % 120000;
    }

    function Init(address _Hospital, address _ComputingParty) public {
        require(inited == false);
        require(ContractCreator == msg.sender);
        Hospital = _Hospital;
        ComputingParty = _ComputingParty;
        inited = true;
    }
    
    function storeGenome(uint256 _datahash, uint256 _medicalhash, uint256 _hashkey1, uint256 _hashkey2, address _keyholder1, address _keyholder2, string memory _nickname) public {
        require(!nicknameExistance[_nickname]);
        require(step1 == false);
        require(step2 == false);
        require(step3 == false);
        require(step4 == false);
        require(step5 == false);
        nicknameExistance[_nickname] = true;
        nicknameList.push(_nickname);
        nickname2genome[_nickname] = Genome_info(true, _datahash, _medicalhash, _hashkey1, _hashkey2, _keyholder1, _keyholder2, msg.sender);
        IndivNum += 1;

        nicknameNeedShare[_nickname] = false;
        nicknameKey1NeedShare[_nickname] = false;
        nicknameKey2NeedShare[_nickname] = false;

        
        emit DataStored(_nickname, IndivNum);  
    }


    function QueryIndivNum() public view returns (uint256) {
        return IndivNum;
    }

    function changesharestate(string calldata _nickname, bool _newstate) public {
        require(nicknameExistance[_nickname]);
        require(nickname2genome[_nickname].dataowner == msg.sender);
        require(step1 == false);
        require(step2 == false);
        require(step3 == false);
        require(step4 == false);
        require(step5 == false);
        if (_newstate == true && nickname2genome[_nickname].sharestate == false){
            nickname2genome[_nickname].sharestate = _newstate;        
            emit StateChanged(_nickname, _newstate);
            IndivNum += 1;
        }else if (_newstate == false && nickname2genome[_nickname].sharestate == true){
            nickname2genome[_nickname].sharestate = _newstate;        
            emit StateChanged(_nickname, _newstate);
            IndivNum -= 1;
        }    
    }

    function QueryGenome(string memory _nickname) public view returns (Genome_info memory) {
        require(nickname2genome[_nickname].dataowner == msg.sender);
        return nickname2genome[_nickname];
    }

    function QueryStep1(uint256 _ParticipantNum, string memory _rsid) public {
        require(step1 == false);
        require(step2 == false);
        require(step3 == false);
        require(step4 == false);
        require(step5 == false);
        require(_ParticipantNum >= 200);
        require(_ParticipantNum <= IndivNum);
        step1 = true;
        QueryInitiator = msg.sender; 

        IndivKey1Submitted = 0;
        IndivKey2Submitted = 0;
        ParticipantNum = _ParticipantNum;
        ParticipantProvided = 0;
        rsid = _rsid;
        emit QueryInited(_rsid, _ParticipantNum);
    }

    function QueryStep2_ProvideSet(string memory _nickname, uint256 _hash) public {
        require(step1 == true);
        require(step2 == false);
        require(step3 == false);
        require(step4 == false);
        require(step5 == false);
        require(Hospital == msg.sender);
        require(nicknameExistance[_nickname] == true);
        require(nickname2genome[_nickname].sharestate == true);
        require(nicknameNeedShare[_nickname] == false);

        ParticipantProvided += 1;
        nicknameKey1NeedShare[_nickname] = true;
        nicknameKey2NeedShare[_nickname] = true;
        nicknameNeedShare[_nickname] = true;

        uint256 boxid = BoxID(_nickname);

        emit IndivRecommend(_nickname, _hash, boxid);

        if (ParticipantProvided == ParticipantNum) {
            step2 = true;
        }
    }

    function QueryStep3() public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == false);
        require(step4 == false);
        require(step5 == false);
        require(ComputingParty == msg.sender);
        step3 = true;
    }

    function QueryStep4_SubmitKey1(uint256 _proofhash, uint256 _witnesshash, string memory _nickname) public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == true);
        require(step4 == false);
        require(step5 == false);
        require(nicknameExistance[_nickname] == true);
        require(nickname2genome[_nickname].sharestate == true);
        require(nickname2genome[_nickname].keyholder1 == msg.sender);
        require(nicknameKey1NeedShare[_nickname] == true);

        nicknameKey1NeedShare[_nickname] = false;
        if (nicknameKey2NeedShare[_nickname] == false){
            nicknameNeedShare[_nickname] = false;
        }

        IndivKey1Submitted += 1;

        emit Key1Submitted(_proofhash, _witnesshash, _nickname);

    }

    function QueryStep4_SubmitKey2(uint256 _proofhash, uint256 _witnesshash, string memory _nickname) public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == true);
        require(step4 == false);
        require(step5 == false);
        require(nicknameExistance[_nickname] == true);
        require(nickname2genome[_nickname].sharestate == true);
        require(nickname2genome[_nickname].keyholder2 == msg.sender);
        require(nicknameKey2NeedShare[_nickname] == true);

        nicknameKey2NeedShare[_nickname] = false;
        if (nicknameKey1NeedShare[_nickname] == false){
            nicknameNeedShare[_nickname] = false;
        }

        IndivKey2Submitted += 1;

        emit Key2Submitted(_proofhash, _witnesshash, _nickname);

    }

    function QueryStep4_ReceivedAll() public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == true);
        require(step4 == false);
        require(step5 == false);
        require(IndivKey1Submitted  == ParticipantNum);
        require(IndivKey2Submitted  == ParticipantNum);
        require(ComputingParty == msg.sender);
        step4 = true;
    }

    function QueryStep5_FinishCalculation(uint256 _reshash) public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == true);
        require(step4 == true);
        require(step5 == false);
        require(ComputingParty == msg.sender);
        step5 = true;
        emit ComputingFinished(_reshash);
    }

    function ClosedQuery() public {
        require(step1 == true);
        require(step2 == true);
        require(step3 == true);
        require(step4 == true);
        require(step5 == true);
        require(QueryInitiator == msg.sender);
        step1 = false;
        step2 = false;
        step3 = false;
        step4 = false;
        step5 = false;
    }


}