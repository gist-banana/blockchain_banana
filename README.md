# blockchain_banana
repository for blockchain course 

=================== 2019 /05 /22 ====================
in blockchain.bring_current_transactions() :
1. pushes current_transactions from registered nodes automatically
* However, it pushes only the first element of the current_transactions
* However, it does not delete the pushed element from the current_transactions from other nodes
(Instead of pushing the element into my current_transactions node, I can just push it directly into transactions() cue. It will decrease the time of transactions being pushed into the transaction)
> Need to fix:
- Figure a way to signal the original node that the element has been added to my node and if the original node receives confirmation from all the nodes registered, it deletes the element that was pushed
- Figure a way out to signal the nodes that a new element has been added to the current_transactions queue
- Figure a way out to have EVERY ELEMENT SENT from the current_transactions queue
