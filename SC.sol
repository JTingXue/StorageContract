pragma solidity ^0.4.0;

contract SC {

/*
state	meaning
0.	Contract has been created, and Owner has deposited.
1.	Owner has uploaded data (for checking and auditing).
2.	All lessors has deposited.
3.	All lessors has voted to choose a block of(index is i) data for checking.
4.	Owner has revealed the Ki.
	Contract will check the integrity of data(h(salt')==h(salt),h(root')==h(root)).
	  -- if accepted, go to 5.
	  -- if rejected, return all deposit of owner and lessors and end contract
5.	All lessor have submitted corresponding leaves for checking.
	  -- if accepted (h(MT(leaves))==h(root)), go to 6.
	  -- if rejected, return all deposit of owner and lessors and end contract
6.	audit
	  1) Owner has sent index of data (uploaded in 1.) and salt, contract will verify the salt.
	  2) Lessors send leaves for auditing.
	  3) When all lessors has sent leaves, contract starts to audit.
		-- if accepted, give bonus
			-- if amount of audit is out, return deposit and end contract.
			-- otherwise, go to 6.
		-- if rejected, go to 7.
7.	Owner judge which lessors submitted bad leaves and owner send right leaves and contract verifies.
	  -- if accepted, punish the cheating lessors (expropriate their deposit), and return others' deposit and end contract.
	  -- if rejected, simply return deposit of owner and all lessors.
*/
    uint public state;
    string public notice;
    
    uint public auditAmount;
    
    address addrO;
    uint depO;
    uint public bonus;
    
    address[] addrL;
    uint sdepL;
    uint[] depL;
    uint[] sureL;
    
    bytes32[] data;
    uint checkIndex;
    uint[] voteIndex;
    uint[] isVoted;
    
    
    uint currentMTIndex;
    bytes32 public currentSalt;
    bytes32[] currentLeaves;
    
    
    event logCreationError(string info);
    event logCreationSuccess(address owner, uint deposit);
    function SC(uint amount, address[] addr, uint sdep) public payable {
        if(addr.length == 0 || amount == 0) {
            logCreationError("Fail to create SC. Input is bad.");
            selfdestruct(msg.sender);
            return;
        }
        auditAmount = amount;
        addrO = msg.sender;
        depO = msg.value;
        bonus = depO/addr.length/auditAmount;
        
        addrL = addr;
        sdepL = sdep;
        depL = new uint[](addrL.length);
        voteIndex = new uint[](auditAmount+1);
        isVoted = new uint[](addrL.length);
        currentLeaves = new bytes32[](addrL.length);
        
        logCreationSuccess(addrO, depO);
        
        state = 0;
        notice = "Contract has been created. Owner should upload data.";
    }
    
    
    event logUploadData(bytes32[] data);
    function uploadData(bytes32[] _data) public {
        if(msg.sender != addrO) {
            return;
        }
        if(state != 0) {
            return;
        }
        if(_data.length != 4*(auditAmount+1)) {
            return;
        }
        
        data = _data;
        logUploadData(data);
        
        state = 1;
        notice = "Owner has uploaded data. Lessors should deposit.";
    }
    
    
    event logLessorDeposit(address lessor, uint depositSum);
    event logFinishDeposit();
    function depositL() public payable {
        if(state != 1) {
            msg.sender.transfer(msg.value);
            return;
        }
        
        uint indexL = 0;
        for(; indexL < addrL.length; indexL++) {
            if(addrL[indexL] == msg.sender)
                break;
        }
        if(indexL >= addrL.length) {
            msg.sender.transfer(msg.value);
            return;
        } else {
            depL[indexL] += msg.value;
            logLessorDeposit(msg.sender, depL[indexL]);
        }
        
        state = 2;
        for(uint i = 0; i < addrL.length; i++) {
            if(depL[i] < sdepL) {
                state = 1;
                break;
            }
        }
        
        if(state == 2) {
            logFinishDeposit();
            notice = "All lessor have finished depositting. Lessors should vote on which index should be checked.";
        }
        
    }
    
    event logVote(address voter, uint index);
    event logFinishVote(uint resultIndex);
    function voteCheckIndex(uint index) public {
        if(state != 2) {
            return;
        }
        
        uint i = 0;
        for(i = 0; i < addrL.length; i++) {
            if(addrL[i] == msg.sender) {
                if(isVoted[i] == 0) {
                    voteIndex[index%voteIndex.length] += 1;
                    isVoted[i] = 1;
                    logVote(msg.sender, index%voteIndex.length);
                    break;
                }
            }
        }
        
        if(i == addrL.length)
            return;
        
        uint count = 0;
        for(i = 0; i < isVoted.length; i++) {
            if(isVoted[i] != 0)
                count++;
        }
        if(count == isVoted.length) {
            checkIndex = 0;
            uint max = 0;
            for(i = 0; i < voteIndex.length; i++) {
                if(voteIndex[i] > max) {
                    checkIndex = i;
                    max = voteIndex[i];
                }
            }
            logFinishVote(checkIndex);
            state = 3;
            notice = "The index has been desided. Owner should reveal the corresponding key to open his commitment.";
        }
    }
    
    
    
    
    function decrypt (bytes32 key, bytes32[] ciphertext) pure private returns(bytes32[] plaintext) {
        if(ciphertext.length == 0)
            return;
        
        bytes32 subKey = sha256(key);
            
        plaintext = new bytes32[](ciphertext.length);
            
        for(uint i = 0; i < ciphertext.length; i++) {
            plaintext[i] = ciphertext[i]^subKey;
            if(i < ciphertext.length-1) {//avoid unnecessary sha256
                subKey = sha256(subKey);
            }
        }
        return plaintext;
    }
    event logRevealKeyError(string result);
    event logRevealKeySuccess(bytes32 salt);
    function revealKey(bytes32 key) public {
        
        if(state != 3 || msg.sender != addrO) {
            return;
        }
        
        bytes32[] memory c = new bytes32[](2);
        c[0] = data[checkIndex*4];
        c[1] = data[checkIndex*4+1];
        bytes32 h_salt = data[checkIndex*4+2];
        bytes32 h_root = data[checkIndex*4+3];
        bytes32[] memory m = decrypt(key, c);
        
        
        uint i = 0;
        if(sha256(m[0]) != h_salt) {
            logRevealKeyError("Fail to reveal key. Selfdestruct and return ethers.");
            for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(depL[i]);
            }
            selfdestruct(addrO);
            return;
        }
        if(sha256(m[1]) != h_root) {
            logRevealKeyError("Fail to reveal key. Selfdestruct and return ethers.");
            for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(depL[i]);
            }
            selfdestruct(addrO);
            return;
        }
        
        logRevealKeySuccess(m[0]);
        currentSalt = m[0];
        currentMTIndex = checkIndex;
        state = 4;
        notice = "Succeed to reveal key. Lessors should send their audit data.(the leaf hash of MT)";
    }
    
    
    
    function generateMerkleTree() view private returns(bytes32 root) {
        bytes32[] memory a;
        a = currentLeaves;
        bytes32[] memory b;
        //padding = 1, need to pad, and padding with 000000; padding == 0, no need to pad.
        uint padding = a.length%2;
        bytes32 emptyNode = 0x0;
        
        uint cur_a = 0;
        uint cur_b = 0;
        
        while(a.length != 1) {
            
            if(padding == 1) {
                b = new bytes32[](a.length/2 + 1);
            } else if(padding == 0){
                b = new bytes32[](a.length/2);
            } else {
                //error
                return;
            }
            
            cur_b = 0;
            for(cur_a = 0; cur_a < (a.length - padding); cur_a+=2) {
                // b[cur_b++] = a[cur_a] + a[cur_a+1];
                b[cur_b++] = sha256(currentSalt, a[cur_a], a[cur_a+1]);
            }
            
            if(padding == 1) {
                // b[cur_b] = a[cur_a] + 0;
                b[cur_b] = sha256(currentSalt, a[cur_a], emptyNode);
            }
            a = b;
            padding = a.length%2;
        }
        
        return a[0];
    }
    event logLessorSendLeaf(address lessor, uint leafIndex, bytes32 leafValue);
    event logCheckAccept();
    event logCheckReject(string result);
    function checkSendLeaf(bytes32 leaf) public {
        if(state != 4) {
            return;
        }
        
        uint i = 0;
        for(i = 0; i < addrL.length; i++) {
            if(addrL[i] == msg.sender) {
                currentLeaves[i] = leaf;
                logLessorSendLeaf(msg.sender, i, leaf);
            }
        }
        
        for(i = 0; i < currentLeaves.length; i++) {
            if(currentLeaves[i] == 0) {
                return;
            }
        }
        
        //check the validate and go on.
        bytes32 mtRoot = generateMerkleTree();
        if(sha256(mtRoot) == data[currentMTIndex*4+3]) {
            logCheckAccept();
            state = 5;
            notice = "Owner should send a salt for audit.";
            for(i = 0; i < currentLeaves.length; i++) {
                currentLeaves[i] = bytes32(0);
            }
        } else {
            logCheckReject("Fail to agree with this contract. Return ethers and selfdestruct.");
            for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(depL[i]);
            }
            selfdestruct(addrO);
            return;
        }
        
    }
    
    
    event logOwnerSendBadSalt(string result);
    event logOwnerSendSalt(bytes32 salt, uint index);
    function auditSendSalt(uint index, bytes32 salt) public {
        if(state != 5 || msg.sender != addrO) {
            return;
        }
        currentSalt = salt;
        currentMTIndex = index;
        
        uint i = 0;
        
        if(sha256(salt) != data[index*4+2]) {
            logOwnerSendBadSalt("Owner will be punished. Return lessor's ethers and carve up owner's ether. selfdestruct.");
            for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(depL[i]+depO/addrL.length);
            }
            selfdestruct(addrO);
            return;
        }
        logOwnerSendSalt(salt, index);
        notice = "Lessors should send audit data.";
    }
    
    
    event logLessorSendLeafAudit(address lessor, uint leafIndex, bytes32 leafValue);
    event logAuditSuccess(string result);
    event logAuditOver(string result);
    event logAuditError(string result);
    function auditSendLeaf(bytes32 leaf) public {
        if(state != 5) {
            return;
        }
        uint i = 0;
        for(i = 0; i < addrL.length; i++) {
            if(addrL[i] == msg.sender) {
                currentLeaves[i] = leaf;
                logLessorSendLeafAudit(msg.sender, i, leaf);
            } 
        }
        for(i = 0; i < currentLeaves.length; i++) {
            if(currentLeaves[i] == 0) {
                return;
            }
        }
        bytes32 mtRoot = generateMerkleTree();
        if(sha256(mtRoot) == data[currentMTIndex*4+3]) {
            logAuditSuccess("Lessors get bonus.");
            state = 5;
            for(i = 0; i < currentLeaves.length; i++) {
                currentLeaves[i] = bytes32(0);
            }
            auditAmount--;
            for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(bonus);
            }
            if(auditAmount == 0) {
                logAuditOver("Audit is over. Return ethers respectively.");
                for(i = 0; i < addrL.length; i++) {
                    addrL[i].transfer(depL[i]);
                }
                selfdestruct(addrO);
                return;
            } else {
                notice = "Owner should send a salt for audit.";
            }
        } else {
            logAuditError("Fail to audit, wait for Owner provides correct leaves.");
            state = 7;
            notice = "Owner should send the correct leaves";
        }
    }
    
    
    event logPunishLessor(address lessor, string result);
    event logPunishNobody(string result);
    function auditPunishL(uint[] index, bytes32[] correctLeaf) public {
        if(state != 7 || msg.sender != addrO || index.length != correctLeaf.length) {
            return;
        }
        uint i = 0; 
        uint[] memory isPunished = new uint[](addrL.length); //default as 0
        
        for(i = 0; i < correctLeaf.length; i++) {
            if(currentLeaves[index[i]] == correctLeaf[i])
                return;
            currentLeaves[index[i]] = correctLeaf[i];
            isPunished[index[i]] = 1;
        }
        
        bytes32 root = generateMerkleTree();
         
        
        if(sha256(root) == data[currentMTIndex*4+3]) {
            for(i = 0; i < addrL.length; i++) {
                if(isPunished[i] == 0) {
                    addrL[i].transfer(depL[i]);
                } else {
                    logPunishLessor(addrL[i], "selfdestruct");
                }
            }
        } else {
             for(i = 0; i < addrL.length; i++) {
                addrL[i].transfer(depL[i]);
            }
            logPunishNobody("This is due to the owner also provided incorrect leaves. selfdestruct");
        }
        
        selfdestruct(addrO);
    }
    
   
    
}