import { 
    Field,
    SmartContract,
    UInt64,Struct, 
    Poseidon, 
    state, 
    State, 
    method ,
    Circuit, 
    Bool,
    Provable
   } from 'o1js';
 
 /*
 
 Struct MMR
 leavesCount
 elementsCount
 hashes
 RootHash
 
 
 Functions:
 
 Append
 GetProof
 VerifyProof
 GetProofs
 VerifyProofs
 GetPeaks
 BagThePeaks
 CalculateRootHash
 RetrievePeaksHashes
 Clear
 
 Utility Functions:
 mapLeafIndexToElementIndex(leafIndex: number)
 mapElementIndexToLeafIndex(elementIndex: number)
 

 */
 
 
 const MAX_ELEMENTS = 2097151;  // 2,097,151 = 2^(h+1)-1   max_height=20
 const MAX_LEAFS = 1048576 //2^10  = 1,048,576
 
 /**
  * Merkle Mountain Range class.
  */
  class MerkleMountainRange extends Struct({
   leavesCount : UInt64,
   elementsCount: UInt64,
   hashes: [Field, MAX_ELEMENTS],
   rootHash: Field,
 }) {
   constructor() {
 
     const initialData = Array(MAX_ELEMENTS).fill(Field(0));
     super({
       leavesCount: UInt64.zero,
       elementsCount: UInt64.zero,
       hashes: initialData,
       rootHash: new Field(0),
     });
   }
 
   /**
    * Append a new leaf to the MMR.
    * @param {Field} data - The data to add to the MMR.
    */
 
    append(data : Field) {
     // Validate input
     if (!(data instanceof Field)) {
       throw new Error('Data must be an instance of Field.');
     }
 
     // Increment leaves count
     this.leavesCount = this.leavesCount.add(1);
 
     // Hash the data to create the leaf hash
     const leafHash = Poseidon.hash([data]);
 
     // Increment elements count and store the leaf hash
     this.elementsCount = this.elementsCount.add(1);
     const elementIndex = this.elementsCount.toBigInt();
     this.hashes[0] =leafHash;
     console.log(leafHash)
     return leafHash;
     // Build the peaks and update the MMR
     //this._buildPeaks(leafHash, elementIndex);
 
     // Update the root hash
     //this.rootHash = this._bagPeaks();
   }
 
   count_ones(n: number) {
     let sum = 0;
     while (n) {
         sum++;
         n &= n - 1;
     }
     return sum;
   }
 
   leaf_count_to_mmr_size(leaf_count: number) {
     return 2 * leaf_count - this.count_ones(leaf_count);
   }
 }
 
 export class Mmr extends SmartContract {
   @state(Field) num = State<Field>();
   @state(Field) leavesCount = State<Field>();
 
   init() {
     super.init();
     this.num.set(Field(2));
     const initialMMR = new MerkleMountainRange();
     this.num.set(initialMMR.append(Field(1)));
     const a = initialMMR.append(Field(1))
     const leafHash = Poseidon.hash([Field(1)]);
     //console.log("leaf", leafHash);
     //console.log("a", a);
     // if(leafHash==a){
     //   this.num.set(Field(1));
     //   console.log("selamm")
     // }
     const x = Provable.if(new Bool(leafHash.equals(a)), Field(1), Field(5));
     console.log(this.num, "syao");
     console.log(x);
     this.num.set(x);
   }
 
   @method async update() {
     const currentState = this.num.getAndRequireEquals();
     const newState = currentState.add(2);
     this.num.set(newState);
   }
 }
 