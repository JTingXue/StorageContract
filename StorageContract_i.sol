pragma solidity ^0.4.0;

contract StorageContract_i {
    
    address ownerAddress;
    address lessorAddress;
    uint ownerDeposit;
    uint ownerShouldDeposit;
    uint bonus;
    uint lessorDeposit;
    uint lessorShouldDeposit;
    uint taskAmount;
    uint taskCounter;
    bytes32 currentTaskHash;
    uint creatingBlockNumber;
    uint maxBlockAmount;
    
   // Constructor, called when the contract is created
    function StorageContract_i(address lessorAddr, uint amount, uint ownerSD, uint lessorSD) public {
        ownerAddress = msg.sender;
        lessorAddress = lessorAddr; 
        taskAmount = amount;
        taskCounter = 0;
        creatingBlockNumber = block.number;
        maxBlockAmount = 3;//related to the interval of withdrawing
        ownerShouldDeposit = ownerSD;
        lessorShouldDeposit = lessorSD;
        currentTaskHash = 0x0;//Suppose the currentTaskHash is 0
        
        if(taskAmount != 0)
            bonus = ownerShouldDeposit/taskAmount;
        else
            bonus = 0;
    }
    
    event LogError(string error);
    
    event LogDestruct(string destruct);
    
    // Filter, which is used to ensure that the message sender is
	// owner, otherwise invalid
    modifier onlyOwner {
        require(msg.sender == ownerAddress);
        _;
    }
    modifier onlyLessor {
        require(msg.sender == lessorAddress);
        _;
    }
    
    
    // Record asset mortgage
    event LogPledge(string who, uint deposit, uint total, bool isEnough);
    
    // Asset mortgage transfer
    function pledge() public payable {
        if(msg.sender == ownerAddress) {
            ownerDeposit = ownerDeposit + msg.value;
            LogPledge("Owner", msg.value, ownerDeposit, ownerDeposit >= ownerShouldDeposit);
        } else if (msg.sender == lessorAddress) {
            lessorDeposit = lessorDeposit + msg.value;
            LogPledge("Lessor", msg.value, lessorDeposit, lessorDeposit >= lessorShouldDeposit);
        }
    }
    
    // Asset mortgage withdrawn
    function withdraw() public {
        uint currentBlockNumber = block.number;
        if(msg.sender == ownerAddress || msg.sender == lessorAddress) {
            if(currentBlockNumber - creatingBlockNumber > maxBlockAmount) {
                ownerAddress.transfer(ownerDeposit);
                lessorAddress.transfer(lessorDeposit);
                LogDestruct("time up, withdraw.");
                selfdestruct(msg.sender);
            } else {
                
                LogError("fail to withdraw.");
            }
        }
    }
    
    
    event LogNewTask(string, bytes32 newTaskHash, uint index);
    
    
    function ownerSubmit(bytes32 taskHash) public onlyOwner {
        if(ownerDeposit < ownerShouldDeposit) {
            LogError("[Owner Sumbit] owner does not pledge.");
            return;
        }
		
        if(lessorDeposit < lessorShouldDeposit) {
            LogError("[Owner Sumbit] lessor does not pledge.");
            return;
        }
        
        if(currentTaskHash == 0x0) {
            currentTaskHash = taskHash;
            taskCounter++;
            LogNewTask("New Task", currentTaskHash, taskCounter);
        } else {
            LogError("lessor has not completed te last task or there is no more task can be done.");
        }
    }
    
    event LogTaskDone(string, bytes32 digest, uint index);
    
    function lessorSubmit(bytes32 digest) public onlyLessor {
        if(ownerDeposit < ownerShouldDeposit) {
            LogError("[Lessor Sumbit] owner does not pledge.");
            return;
        }
        if(lessorDeposit < lessorShouldDeposit) {
            LogError("[Lessor Sumbit] lessor does not pledge.");
            return;
        }
        if(currentTaskHash == 0x0) {
            LogError("[Lessor Sumbit] owner dose not submit taskHas.");
            return;
        }
          
        if(sha256(digest) == currentTaskHash) {
            lessorAddress.transfer(bonus);
            LogTaskDone("Task Done", digest, taskCounter);
            currentTaskHash = 0x0;
            
            // Return the assets mortgage and destroy the contract
			// after the last audit certificate has come into effect
            if(taskCounter >= taskAmount) {
                lessorAddress.transfer(lessorDeposit);
                LogDestruct("amount up, withdraw.");
                selfdestruct(ownerAddress);
            }
        } else {
            LogDestruct("lessor submit wrong digest.");
            selfdestruct(ownerAddress);
        }
    }
}