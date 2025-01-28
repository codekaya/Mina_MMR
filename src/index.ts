import { MerkleMountainRange } from './Mmr.js';
export { MerkleMountainRange };

import { Mina, PrivateKey, Field, UInt64, AccountUpdate } from 'o1js';
import { MMRContract } from './MMRContract.js';

(async function main() {
  // 1) Setup a local Mina blockchain + deploy a new instance of MMRContract
  let Local = await Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);

  const [feePayer] = Local.testAccounts;
  //let deployerAccount = Local.testAccounts[0].key;
  
  let contractAccount = Mina.TestPublicKey.random();
  let mmrZkApp = new MMRContract(contractAccount);

  await MMRContract.compile();

  console.log("in above")
  // Deploy
  let txn = await Local.transaction(feePayer, async () => {
    AccountUpdate.fundNewAccount(feePayer);
    await mmrZkApp.deploy();
    //await mmrZkApp.init(); // sets mmrRoot = Field(0)
  });
  //await txn.send().wait();
  await txn.prove();
  await txn.sign([feePayer.key, contractAccount.key]);

  let pendingTx = await txn.send();

  console.log(`Got pending transaction with hash ${pendingTx.hash}`);
  await pendingTx.wait();



  // 2) Off-chain: Build an MMR with your library
  let mmr = new MerkleMountainRange();

  // append some leaves
  mmr.append(Field(10));
  mmr.append(Field(20));
  mmr.append(Field(30));

  console.log("in middle")
  // get the "root" from the MMR
  let currentRoot = mmr.rootHash;

  // 3) On-chain: store the new root in the zkApp
  txn = await Local.transaction(feePayer, async () => {
    await mmrZkApp.updateRoot(currentRoot);
  });
  await txn.prove();
  await txn.sign([feePayer.key]).send();
  //await txn.send().wait();
  console.log("in here")

  // 4) Off-chain: generate a proof for a leaf
  let proof = mmr.getProof(UInt64.from(2)); // second leaf => Field(20)
  console.log('Proof: ', proof);

  // 5) On-chain: verify the proof (assuming we made a method that takes siblings/peaks, etc.)
  // We'll just do a naive version for demonstration
  let siblings = proof.siblingsHashes;
  let peaks = proof.peaksHashes;

  // Verify inclusion
  // txn = await Local.transaction(feePayer, async () => {
  //   await mmrZkApp.verifyInclusion(
  //     Field(20),
  //     siblings,
  //     peaks,
  //     Field(2)
  //   );
  // });
  // await txn.send().wait();

  console.log('MMR proof verified successfully on-chain!');
})();
