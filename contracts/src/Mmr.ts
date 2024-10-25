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
 append(data : Field) 
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
 count_ones(n: number)
 findPeaks(elementCount: UInt64): UInt64[]
 bintreeJumpRightSibling(elementIndex: UInt64): UInt64
 bintreeMoveDownLeft(elementIndex: UInt64): UInt64
 getHeight(elementIndex: UInt64): UInt64
 allOnes(num: UInt64): Bool
 pow2(exponent: UInt64): UInt64
 bitLength(num: UInt64): UInt64
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
     this.hashes[Number(elementIndex)] =leafHash;
     console.log(leafHash)
     return leafHash;
     // Build the peaks and update the MMR
     //this._buildPeaks(leafHash, elementIndex);
 
     // Update the root hash
     //this.rootHash = this._bagPeaks();
   }
 
//    append(value) {
//     if (!this.isElementSizeValid(value)) {
//       throw new Error("Element size is too big to hash with this hasher");
//     }

//     const elementsCount = this.elementsCount;
//     const peaksIndices = findPeaks(elementsCount);
//     const peaks = this.retrievePeaksHashes(peaksIndices);

//     // Increment elementsCount
//     this.elementsCount = this.elementsCount.add(UInt64.one);
//     let lastElementIdx = this.elementsCount;

//     const leafElementIndex = lastElementIdx;

//     // Store the new value at the last index
//     this.hashes.set(lastElementIdx.toString(), value);

//     // Add the new value to peaks
//     peaks.push(value);

//     let height = UInt64.zero;

//     // Loop to update peaks and compute parent hashes
//     while (getHeight(lastElementIdx.add(UInt64.one)).greaterThan(height).toBoolean()) {
//       lastElementIdx = lastElementIdx.add(UInt64.one);

//       const rightHash = peaks.pop();
//       const leftHash = peaks.pop();

//       const parentHash = this.hasher.hash([leftHash, rightHash]);
//       this.hashes.set(lastElementIdx.toString(), parentHash);
//       peaks.push(parentHash);

//       height = height.add(UInt64.one);
//     }

//     // Update elementsCount with the last index used
//     this.elementsCount = lastElementIdx;

//     // Bag the peaks to compute the final root hash
//     this.peaks = peaks; // Store the updated peaks
//     const bag = this.bagThePeaks();
//     const rootHash = this.calculateRootHash(bag, lastElementIdx);
//     this.rootHash = rootHash;

//     // Increment leavesCount
//     this.leavesCount = this.leavesCount.add(UInt64.one);

//     // Return the updated counts and root hash
//     return {
//       leavesCount: this.leavesCount,
//       elementsCount: this.elementsCount,
//       elementIndex: leafElementIndex,
//       rootHash: this.rootHash,
//     };
//   }

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
//-------FIND PEAKS---------------
/**
 * Finds the peaks in a Merkle Mountain Range (MMR) given the element count.
 * @param elementCount The number of elements in the MMR.
 * @returns An array of peak positions.
 */
function findPeaks(elementCount: UInt64): UInt64[] {
  if (elementCount.equals(UInt64.zero).toBoolean()) return [];

  const peaks: UInt64[] = [];
  let top = UInt64.one;

  // Find the largest power of 2 <= elementCount
  while (top.sub(UInt64.one).lessThanOrEqual(elementCount).toBoolean()) {
    top = top.mul(UInt64.from(2));
  }
  top = top.div(UInt64.from(2)).sub(UInt64.one);

  if (top.equals(UInt64.zero).toBoolean()) return [UInt64.one];

  // Initialize with the first peak
  let peak = top;
  peaks.push(peak);
  let outer = true;

  while (outer) {
    peak = bintreeJumpRightSibling(peak);

    while (peak.greaterThan(elementCount).toBoolean()) {
      peak = bintreeMoveDownLeft(peak);
      if (peak.equals(UInt64.zero).toBoolean()) {
        outer = false;
        break;
      }
    }

    if (outer) peaks.push(peak);
  }

  return peaks;
}

// Helper functions

function bintreeJumpRightSibling(elementIndex: UInt64): UInt64 {
  const height = getHeight(elementIndex);
  const shiftAmount = height.add(UInt64.one);
  const increment = pow2(shiftAmount).sub(UInt64.one);
  return elementIndex.add(increment);
}

function bintreeMoveDownLeft(elementIndex: UInt64): UInt64 {
  const height = getHeight(elementIndex);
  if (height.equals(UInt64.zero).toBoolean()) {
    return UInt64.zero;
  }
  const decrement = pow2(height);
  return elementIndex.sub(decrement);
}

function getHeight(elementIndex: UInt64): UInt64 {
  let h = elementIndex;
  while (allOnes(h).not().toBoolean()) {
    const highestBit = pow2(bitLength(h).sub(UInt64.one));
    h = h.sub(highestBit.sub(UInt64.one));
  }
  return bitLength(h).sub(UInt64.one);
}

function allOnes(num: UInt64): Bool {
  const ones = pow2(bitLength(num)).sub(UInt64.one);
  return num.equals(ones);
}

function bitLength(num: UInt64): UInt64 {
  // Compute the bit length of num
  let length = UInt64.zero;
  let temp = num;

  while (temp.greaterThan(UInt64.zero).toBoolean()) {
    temp = temp.div(UInt64.from(2));
    length = length.add(UInt64.one);
  }

  return length;
}

function pow2(exponent: UInt64): UInt64 {
  // Compute 2^exponent
  let result = UInt64.one;
  const two = UInt64.from(2);
  let exp = exponent;

  while (exp.greaterThan(UInt64.zero).toBoolean()) {
    result = result.mul(two);
    exp = exp.sub(UInt64.one);
  }

  return result;
}


//----------------------------------------

 
 
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

     // Example usage
    const elementCount = UInt64.from(22); // example element count
    const peaks = findPeaks(elementCount);
    console.log('Peaks:', peaks.map((p) => p.toString())); // Outputs the peak positions in the MMR
   }
 
   @method async update() {
     const currentState = this.num.getAndRequireEquals();
     const newState = currentState.add(2);
     this.num.set(newState);
   }
 }
 